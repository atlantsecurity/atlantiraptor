package networking

// Agent identity for mutual TLS with the Atlantiraptor frontend.
//
// When the server asks for a client certificate and names our own CA
// as acceptable, the agent presents a certificate for its own
// communication key (the key its client ID is derived from):
//
//   - If the client configuration carries a deployment certificate
//     (Client.Crypto.client_certificate, signed by the server's CA),
//     the agent's certificate is signed with it and sent together with
//     it. A brand new agent installed by GPO, Intune or an MSI uses
//     this to prove it was deployed by the organization before it has
//     enrolled.
//   - Otherwise the certificate is self-signed. The server accepts it
//     only for agents whose key it already knows (enrolled agents).
//
// The server side is services/agentmtls.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

type agentIdentity struct {
	key       *rsa.PrivateKey
	client_id string

	mu    sync.Mutex
	cache map[[32]byte]*tls.Certificate
}

var (
	agent_identity_mu sync.Mutex
	agent_identity    *agentIdentity
)

// SetAgentKey registers the agent's communication key. The agent's
// communicator calls it at startup; until then (and in server
// processes) no agent certificate is presented.
func SetAgentKey(key *rsa.PrivateKey, client_id string) {
	agent_identity_mu.Lock()
	defer agent_identity_mu.Unlock()
	if key == nil {
		agent_identity = nil
		return
	}
	agent_identity = &agentIdentity{
		key:       key,
		client_id: client_id,
		cache:     make(map[[32]byte]*tls.Certificate),
	}
}

func getAgentIdentity() *agentIdentity {
	agent_identity_mu.Lock()
	defer agent_identity_mu.Unlock()
	return agent_identity
}

// AgentMTLSMarker is the common name of an extra "acceptable CA" an
// Atlantiraptor frontend lists in its certificate request when it
// checks agent certificates (services/agentmtls). Velociraptor's own
// Frontend.require_client_certificates mode does not list it, and
// agents then present the configured client certificate unchanged.
const AgentMTLSMarker = "Atlantiraptor agent mTLS"

// serverWantsAgentCert reports whether the server's certificate
// request names our CA and the agent mTLS marker as acceptable
// issuers. Only then do we send the agent's certificate, so other
// servers that ask for client certificates never learn the client ID.
func serverWantsAgentCert(info *tls.CertificateRequestInfo, ca_pem string) bool {
	if info == nil || ca_pem == "" {
		return false
	}
	marker := false
	for _, name := range info.AcceptableCAs {
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(name, &rdn); err != nil {
			continue
		}
		var n pkix.Name
		n.FillFromRDNSequence(&rdn)
		if n.CommonName == AgentMTLSMarker {
			marker = true
		}
	}
	if !marker {
		return false
	}
	block, _ := pem.Decode([]byte(ca_pem))
	if block == nil {
		return false
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, name := range info.AcceptableCAs {
		if bytes.Equal(name, ca.RawSubject) {
			return true
		}
	}
	return false
}

// parseDeploymentCert returns the configuration's deployment
// certificate and key, or nil if there is none.
func parseDeploymentCert(config_obj *config_proto.ClientConfig) (
	*x509.Certificate, crypto.Signer) {
	c := config_obj.GetCrypto()
	if c == nil || c.ClientCertificate == "" || c.ClientCertificatePrivateKey == "" {
		return nil, nil
	}
	pair, err := tls.X509KeyPair([]byte(c.ClientCertificate),
		[]byte(c.ClientCertificatePrivateKey))
	if err != nil || len(pair.Certificate) == 0 {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil
	}
	return cert, signer
}

// certificate returns the agent's TLS certificate for this
// configuration, building it once per deployment certificate.
func (self *agentIdentity) certificate(
	config_obj *config_proto.ClientConfig) (*tls.Certificate, error) {
	parent, parent_key := parseDeploymentCert(config_obj)

	var cache_key [32]byte
	if parent != nil {
		cache_key = sha256.Sum256(parent.Raw)
	}

	self.mu.Lock()
	defer self.mu.Unlock()
	if cert, ok := self.cache[cache_key]; ok {
		return cert, nil
	}

	cert, err := BuildAgentCertificate(self.key, self.client_id, parent, parent_key)
	if err != nil {
		return nil, err
	}
	self.cache[cache_key] = cert
	return cert, nil
}

// BuildAgentCertificate makes the certificate an agent presents: a
// certificate for its own key, signed by the deployment certificate
// when there is one (and then followed by it), else self-signed.
func BuildAgentCertificate(key *rsa.PrivateKey, client_id string,
	parent *x509.Certificate, parent_key crypto.Signer) (*tls.Certificate, error) {
	if key == nil {
		return nil, errors.New("no agent key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   client_id,
			Organization: []string{"Atlantiraptor agent"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	issuer := template
	var signer crypto.Signer = key
	if parent != nil && parent_key != nil {
		issuer = parent
		signer = parent_key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer,
		&key.PublicKey, signer)
	if err != nil {
		return nil, err
	}

	result := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	if issuer != template {
		result.Certificate = append(result.Certificate, parent.Raw)
	}
	return result, nil
}

// clientCertificateCallback picks the certificate to present when a
// server asks for one.
func clientCertificateCallback(config_obj *config_proto.ClientConfig,
	legacy *tls.Certificate) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if id := getAgentIdentity(); id != nil &&
			serverWantsAgentCert(info, config_obj.GetCaCertificate()) {
			cert, err := id.certificate(config_obj)
			if err == nil {
				return cert, nil
			}
		}

		// Velociraptor's behaviour: present the configured client
		// certificate, e.g. to an mTLS protected tool server.
		if legacy != nil {
			return legacy, nil
		}
		return &tls.Certificate{}, nil
	}
}
