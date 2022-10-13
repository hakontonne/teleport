package keystore

import (
	"crypto"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

type KMSConfig struct {
	KeyRing string
}

type kmsKeyStore struct{}

func NewKMSKeyStore(cfg *KMSConfig) (KeyStore, error) {
	return &kmsKeyStore{}, nil
}

// GenerateRSA creates a new RSA private key and returns its identifier and a
// crypto.Signer. The returned identifier for rawKeyStore is a pem-encoded
// private key, and can be passed to GetSigner later to get the same
// crypto.Signer.
func (c *kmsKeyStore) GenerateRSA() ([]byte, crypto.Signer, error) {
	return nil, nil, trace.NotImplemented("")
}

// GetSigner returns a crypto.Signer for the given pem-encoded private key.
func (c *kmsKeyStore) GetSigner(rawKey []byte) (crypto.Signer, error) {
	return nil, trace.NotImplemented("")
}

// GetTLSCertAndSigner selects the first kms TLS keypair and returns the kms
// TLS cert and a crypto.Signer.
func (c *kmsKeyStore) GetTLSCertAndSigner(ca types.CertAuthority) ([]byte, crypto.Signer, error) {
	return nil, nil, trace.NotImplemented("")
}

// GetAdditionalTrustedTLSCertAndSigner selects the local TLS keypair from the
// CA AdditionalTrustedKeys and returns the PEM-encoded TLS cert and a
// crypto.Signer.
func (c *kmsKeyStore) GetAdditionalTrustedTLSCertAndSigner(ca types.CertAuthority) ([]byte, crypto.Signer, error) {
	return nil, nil, trace.NotImplemented("")
}

// GetSSHSigner selects the first kms SSH keypair and returns an ssh.Signer
func (c *kmsKeyStore) GetSSHSigner(ca types.CertAuthority) (ssh.Signer, error) {
	return nil, trace.NotImplemented("")
}

// GetAdditionalTrustedSSHSigner selects the local SSH keypair from the CA
// AdditionalTrustedKeys and returns an ssh.Signer.
func (c *kmsKeyStore) GetAdditionalTrustedSSHSigner(ca types.CertAuthority) (ssh.Signer, error) {
	return nil, trace.NotImplemented("")
}

// GetJWTSigner returns the active JWT signer used to sign tokens.
func (c *kmsKeyStore) GetJWTSigner(ca types.CertAuthority) (crypto.Signer, error) {
	return nil, trace.NotImplemented("")
}

// NewSSHKeyPair creates and returns a new SSHKeyPair.
func (c *kmsKeyStore) NewSSHKeyPair() (*types.SSHKeyPair, error) {
	return nil, trace.NotImplemented("")
}

// NewTLSKeyPair creates and returns a new TLSKeyPair.
func (c *kmsKeyStore) NewTLSKeyPair(clusterName string) (*types.TLSKeyPair, error) {
	return nil, trace.NotImplemented("")
}

// NewJWTKeyPair creates and returns a new JWTKeyPair.
func (c *kmsKeyStore) NewJWTKeyPair() (*types.JWTKeyPair, error) {
	return nil, trace.NotImplemented("")
}

// DeleteKey deletes the given key from the KeyStore.
func (c *kmsKeyStore) DeleteKey(rawKey []byte) error {
	return trace.NotImplemented("")
}

func (c *kmsKeyStore) keySetHasLocalKeys(keySet types.CAKeySet) bool {
	return true
}

// HasLocalActiveKeys returns true if the given CA has any active keys that
// are usable with this KeyStore.
func (c *kmsKeyStore) HasLocalActiveKeys(ca types.CertAuthority) bool {
	return c.keySetHasLocalKeys(ca.GetActiveKeys())
}

// HasLocalAdditionalKeys returns true if the given CA has any additional
// trusted keys that are usable with this KeyStore.
func (c *kmsKeyStore) HasLocalAdditionalKeys(ca types.CertAuthority) bool {
	return c.keySetHasLocalKeys(ca.GetAdditionalTrustedKeys())
}

// DeleteUnusedKeys deletes all keys from the KeyStore if they are:
// 1. Labeled by this KeyStore when they were created
// 2. Not included in the argument usedKeys
func (c *kmsKeyStore) DeleteUnusedKeys(usedKeys [][]byte) error {
	return trace.NotImplemented("")
}
