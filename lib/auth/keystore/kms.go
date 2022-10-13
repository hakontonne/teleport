package keystore

import (
	"crypto"
	"crypto/x509"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
	"encoding/pem"

	"github.com/gravitational/teleport/api/types"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"github.com/google/uuid"
	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// GCP does not allow "." or "/"
const hostLabel = "teleport_auth_host"

type KMSConfig struct {
	KeyRing string
	HostUUID string
}

type kmsKeyStore struct{
	hostUUID string
	keyRing string
	kmsClient *kms.KeyManagementClient
}

func NewKMSKeyStore(cfg *KMSConfig) (KeyStore, error) {
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &kmsKeyStore{
		hostUUID: cfg.HostUUID,
		keyRing: cfg.KeyRing,
		kmsClient: kmsClient,
	}, nil
}

func newKeyID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return id.String(), nil
}

type kmsSigner struct {
	kmsClient *kms.KeyManagementClient
	keyName string
	public crypto.PublicKey
}

func waitForPending[reqType, optType, respType any](f func(context.Context, reqType, ...optType) (*respType, error), ctx context.Context, req reqType) (*respType, error) {
	for i := 0; i < 9; i++ {
		resp, err := f(ctx, req)
		if err == nil {
			return resp, nil
		}
		if !strings.Contains(err.Error(), "PENDING") {
			return nil, trace.Wrap(err)
		}
		time.Sleep(5*time.Second)
	}
	resp, err := f(ctx, req)
	return resp, trace.Wrap(err)
}

func newKmsSigner(kmsClient *kms.KeyManagementClient, keyName string) (*kmsSigner, error) {
	ctx := context.Background()
	req := &kmspb.GetPublicKeyRequest{
		Name: fmt.Sprintf("%s/cryptoKeyVersions/1", keyName),
	}
	resp, err := waitForPending(kmsClient.GetPublicKey, ctx, req)
	if err != nil {
		return nil, trace.Wrap(err, "unexpected error fetching public key")
	}
	fmt.Printf("NIC GetPublicKey resp: %+v\n", resp)

	block, _ := pem.Decode([]byte(resp.Pem))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, trace.Wrap(err, "unexpected error parsing public key pem")
	}

	return &kmsSigner{
		kmsClient: kmsClient,
		keyName: keyName,
		public: pub,
	}, nil
}

func (s *kmsSigner) Public() crypto.PublicKey {
	return s.public
}

func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	resp, err := s.kmsClient.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: fmt.Sprintf("%s/cryptoKeyVersions/1", s.keyName),
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fmt.Printf("NIC AsymmetricSign resp: %+v\n", resp)
	return resp.Signature, nil
}

// GenerateRSA creates a new RSA private key and returns its identifier and a
// crypto.Signer. The returned identifier for rawKeyStore is a pem-encoded
// private key, and can be passed to GetSigner later to get the same
// crypto.Signer.
func (k *kmsKeyStore) GenerateRSA() ([]byte, crypto.Signer, error) {
	ctx := context.Background()

	keyID, err := newKeyID()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent: k.keyRing,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Labels: map[string]string{
				hostLabel: k.hostUUID,
			},
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			},
		},
	}
	resp, err := k.kmsClient.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	fmt.Printf("NIC CreateCryptoKey resp: %+v\n", resp)
	signer, err := newKmsSigner(k.kmsClient, resp.Name)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return []byte(keyID), signer, nil
}

// GetSigner returns a crypto.Signer for the given pem-encoded private key.
func (k *kmsKeyStore) GetSigner(rawKey []byte) (crypto.Signer, error) {
	keyName := fmt.Sprintf("%s/cryptoKeys/%s", k.keyRing, string(rawKey))
	signer, err := newKmsSigner(k.kmsClient, keyName)
	return signer, trace.Wrap(err)
}

// GetTLSCertAndSigner selects the first kms TLS keypair and returns the kms
// TLS cert and a crypto.Signer.
func (k *kmsKeyStore) GetTLSCertAndSigner(ca types.CertAuthority) ([]byte, crypto.Signer, error) {
	return nil, nil, trace.NotImplemented("GetTLSCertAndSigner not implemented")
}

// GetAdditionalTrustedTLSCertAndSigner selects the local TLS keypair from the
// CA AdditionalTrustedKeys and returns the PEM-encoded TLS cert and a
// crypto.Signer.
func (k *kmsKeyStore) GetAdditionalTrustedTLSCertAndSigner(ca types.CertAuthority) ([]byte, crypto.Signer, error) {
	return nil, nil, trace.NotImplemented("GetAdditionalTrustedTLSCertAndSigner not implemented")
}

// GetSSHSigner selects the first kms SSH keypair and returns an ssh.Signer
func (k *kmsKeyStore) GetSSHSigner(ca types.CertAuthority) (ssh.Signer, error) {
	return nil, trace.NotImplemented("GetSSHSigner not implemented")
}

// GetAdditionalTrustedSSHSigner selects the local SSH keypair from the CA
// AdditionalTrustedKeys and returns an ssh.Signer.
func (k *kmsKeyStore) GetAdditionalTrustedSSHSigner(ca types.CertAuthority) (ssh.Signer, error) {
	return nil, trace.NotImplemented("GetAdditionalTrustedSSHSigner not implemented")
}

// GetJWTSigner returns the active JWT signer used to sign tokens.
func (k *kmsKeyStore) GetJWTSigner(ca types.CertAuthority) (crypto.Signer, error) {
	return nil, trace.NotImplemented("GetJWTSigner not implemented")
}

// NewSSHKeyPair creates and returns a new SSHKeyPair.
func (k *kmsKeyStore) NewSSHKeyPair() (*types.SSHKeyPair, error) {
	return nil, trace.NotImplemented("NewSSHKeyPair not implemented")
}

// NewTLSKeyPair creates and returns a new TLSKeyPair.
func (k *kmsKeyStore) NewTLSKeyPair(clusterName string) (*types.TLSKeyPair, error) {
	return nil, trace.NotImplemented("NewTLSKeyPair not implemented")
}

// NewJWTKeyPair creates and returns a new JWTKeyPair.
func (k *kmsKeyStore) NewJWTKeyPair() (*types.JWTKeyPair, error) {
	return nil, trace.NotImplemented("NewJWTKeyPair not implemented")
}

// DeleteKey deletes the given key from the KeyStore.
func (k *kmsKeyStore) DeleteKey(rawKey []byte) error {
	ctx := context.Background()
	req := &kmspb.DestroyCryptoKeyVersionRequest{
		Name: fmt.Sprintf("%s/cryptoKeys/%s/cryptoKeyVersions/1", k.keyRing, string(rawKey)),
	}
	_, err := waitForPending(k.kmsClient.DestroyCryptoKeyVersion, ctx, req)
	return trace.Wrap(err)
}

func (k *kmsKeyStore) keySetHasLocalKeys(keySet types.CAKeySet) bool {
	return false
}

// HasLocalActiveKeys returns true if the given CA has any active keys that
// are usable with this KeyStore.
func (k *kmsKeyStore) HasLocalActiveKeys(ca types.CertAuthority) bool {
	return k.keySetHasLocalKeys(ca.GetActiveKeys())
}

// HasLocalAdditionalKeys returns true if the given CA has any additional
// trusted keys that are usable with this KeyStore.
func (k *kmsKeyStore) HasLocalAdditionalKeys(ca types.CertAuthority) bool {
	return k.keySetHasLocalKeys(ca.GetAdditionalTrustedKeys())
}

// DeleteUnusedKeys deletes all keys from the KeyStore if they are:
// 1. Labeled by this KeyStore when they were created
// 2. Not included in the argument usedKeys
func (k *kmsKeyStore) DeleteUnusedKeys(usedKeys [][]byte) error {
	return trace.NotImplemented("DeleteUnusedKeys not implemented")
}
