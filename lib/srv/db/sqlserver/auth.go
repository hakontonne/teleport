/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sqlserver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/gravitational/trace"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/kinit"
)

type sqlClientI interface {
	New() (*client.Client, error)
}

type keytabClient struct {
	session *common.Session
}

// New returns a new keytabClient using a keytab file and then logging in with that keytab, which then obtains a TGT
func (k *keytabClient) New() (*client.Client, error) {
	// Load keytab.
	kt, err := keytab.Load(k.session.Database.GetAD().KeytabFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load krb5.conf.
	conf, err := config.Load(k.session.Database.GetAD().Krb5File)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create Kerberos client.
	kbClient := client.NewWithKeytab(
		k.session.DatabaseUser,
		k.session.Database.GetAD().Domain,
		kt,
		conf,
		// Active Directory does not commonly support FAST negotiation.
		client.DisablePAFXFAST(true))

	// Login.
	err = kbClient.Login()
	return kbClient, err
}

type kinitClient struct {
	ctx     context.Context
	session *common.Session
	auth    auth.ClientI
}

// New returns a new kinitClient which configures and instantiates a new credentials cache which obtains a TGT
func (c *kinitClient) New() (*client.Client, error) {
	ldapPem, _ := pem.Decode([]byte(c.session.Database.GetAD().LDAPCert))

	cert, err := x509.ParseCertificate(ldapPem.Bytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var k kinit.ProviderI = kinit.NewCommandProvider(
		c.auth,
		c.session.Identity.Username,
		strings.ToUpper(c.session.Database.GetAD().Domain),
		c.session.Database.GetAD().Domain,
		c.session.Database.GetAD().Domain,
		cert,
	)

	// create the kinit credentials cache using the previously prepared cert/key pair
	err = k.CreateOrAppendCredentialsCache(c.ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load CCache.
	cc, err := credentials.LoadCCache(k.CacheName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load krb5.conf.
	conf, err := config.Load(c.session.Database.GetAD().Krb5File)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create Kerberos client from ccache.
	return client.NewFromCCache(cc, conf, client.DisablePAFXFAST(true))
}

// getAuth returns Kerberos authenticator used by SQL Server driver.
//
// TODO(r0mant): Unit-test this. In-memory Kerberos server?
func (c *connector) getAuth(sessionCtx *common.Session, clientI sqlClientI) (*krbAuth, error) {

	kbClient, err := clientI.New()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Obtain service ticket for the database's Service Principal Name.
	ticket, encryptionKey, err := kbClient.GetServiceTicket(sessionCtx.Database.GetAD().SPN)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create init negotiation token.
	initToken, err := spnego.NewNegTokenInitKRB5(kbClient, ticket, encryptionKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Marshal init negotiation token.
	initTokenBytes, err := initToken.Marshal()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &krbAuth{
		initToken: initTokenBytes,
	}, nil
}

// krbAuth implements SQL Server driver's "auth" interface used during login
// to provide Kerberos authentication.
type krbAuth struct {
	initToken []byte
}

func (a *krbAuth) InitialBytes() ([]byte, error) {
	return a.initToken, nil
}

func (a *krbAuth) NextBytes(bytes []byte) ([]byte, error) {
	return nil, nil
}

func (a *krbAuth) Free() {}
