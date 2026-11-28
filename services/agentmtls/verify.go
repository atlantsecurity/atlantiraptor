package agentmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	crypto_proto "www.velocidex.com/golang/velociraptor/crypto/proto"
	crypto_utils "www.velocidex.com/golang/velociraptor/crypto/utils"
	"www.velocidex.com/golang/velociraptor/datastore"
	"www.velocidex.com/golang/velociraptor/paths"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql/networking"
)

var (
	errNoCertificate = errors.New("agent certificate required")
	errRefused       = errors.New("agent certificate refused")
)

// verdict is what the handshake decides about a peer.
type verdict struct {
	Kind     string
	ClientId string
	OK       bool
	Reason   string
}

// classify decides about the certificates a peer presented, for the
// given settings.
func (self *Service) classify(certs []*x509.Certificate) verdict {
	self.mu.Lock()
	settings := self.settings
	ca := self.ca_cert
	serial := self.deployment_serial
	self.mu.Unlock()

	if len(certs) == 0 {
		return verdict{Kind: KindNone, Reason: "no certificate"}
	}
	leaf := certs[0]

	is_deployment := func(c *x509.Certificate) bool {
		return ca != nil && serial != nil && c.SerialNumber != nil &&
			c.SerialNumber.Cmp(serial) == 0 && c.CheckSignatureFrom(ca) == nil
	}

	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return verdict{Kind: KindOther, Reason: "not an agent certificate"}
	}

	if is_deployment(leaf) {
		if settings.AllowLegacy {
			return verdict{Kind: KindLegacy, OK: true,
				Reason: "older agent with only the deployment certificate"}
		}
		return verdict{Kind: KindLegacy,
			Reason: "older agents with only the deployment certificate are not accepted"}
	}

	client_id := crypto_utils.ClientIDFromPublicKey(pub)
	if self.IsBlocked(client_id) {
		return verdict{Kind: KindOther, ClientId: client_id, Reason: "agent is blocked"}
	}

	if self.keys.known(client_id, pub) {
		return verdict{Kind: KindOwn, ClientId: client_id, OK: true}
	}

	if len(certs) >= 2 && is_deployment(certs[1]) &&
		certs[1].CheckSignature(leaf.SignatureAlgorithm,
			leaf.RawTBSCertificate, leaf.Signature) == nil {
		if settings.AllowEnrollment {
			return verdict{Kind: KindNew, ClientId: client_id, OK: true,
				Reason: "new agent enrolling"}
		}
		return verdict{Kind: KindNew, ClientId: client_id,
			Reason: "new enrollments are paused"}
	}

	if len(certs) >= 2 {
		return verdict{Kind: KindOther, ClientId: client_id,
			Reason: "unknown agent signed by an old or unknown deployment certificate"}
	}
	return verdict{Kind: KindOther, ClientId: client_id, Reason: "unknown agent key"}
}

// marker_cert is listed as an acceptable CA so our agents know this
// frontend checks agent certificates (see networking.AgentMTLSMarker).
var (
	marker_once sync.Once
	marker_cert *x509.Certificate
)

func markerCert() *x509.Certificate {
	marker_once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: networking.AgentMTLSMarker},
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return
		}
		marker_cert, _ = x509.ParseCertificate(der)
	})
	return marker_cert
}

// WrapTLSConfig makes the frontend's TLS configuration follow the
// current mode, handshake by handshake, so changing it in the console
// needs no restart.
func (self *Service) WrapTLSConfig(base *tls.Config) *tls.Config {
	self.mu.Lock()
	ca := self.ca_cert
	self.mu.Unlock()

	pool := x509.NewCertPool()
	if ca != nil {
		pool.AddCert(ca)
	}
	if m := markerCert(); m != nil {
		pool.AddCert(m)
	}

	make_config := func(auth tls.ClientAuthType) *tls.Config {
		c := base.Clone()
		c.ClientAuth = auth
		if auth != tls.NoClientCert {
			c.ClientCAs = pool
		}
		return c
	}
	off := make_config(tls.NoClientCert)
	warn := make_config(tls.RequestClientCert)
	// Enforce also only requests a certificate: verifyConnection
	// refuses connections without one, and records them.
	enforce := make_config(tls.RequestClientCert)

	result := base.Clone()
	result.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		var c *tls.Config
		mode := self.EffectiveMode()
		switch mode {
		case ModeWarn:
			c = warn.Clone()
		case ModeEnforce:
			c = enforce.Clone()
		default:
			return off, nil
		}
		remote := ""
		if hello != nil && hello.Conn != nil && hello.Conn.RemoteAddr() != nil {
			remote = hello.Conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(remote); err == nil {
				remote = host
			}
		}
		is_enforce := mode == ModeEnforce
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			return self.verifyConnection(cs, remote, is_enforce)
		}
		return c, nil
	}
	return result
}

func (self *Service) verifyConnection(cs tls.ConnectionState, remote string, enforce bool) error {
	v := self.classify(cs.PeerCertificates)
	if v.OK {
		return nil
	}
	// Agents without a certificate are counted when their messages
	// arrive; recording each one here in Warn mode would drown out
	// real refusals.
	if v.Kind != KindNone || enforce {
		self.recordRejection(remote, v, enforce)
	}
	if !enforce {
		return nil
	}
	if v.Kind == KindNone {
		return errNoCertificate
	}
	return errRefused
}

func (self *Service) recordRejection(remote string, v verdict, refused bool) {
	self.mu.Lock()
	defer self.mu.Unlock()
	now := self.now().Unix()

	// At most one entry a minute for the same agent (or address) and
	// reason.
	key := v.ClientId + "|" + remote + "|" + v.Reason
	if v.ClientId != "" {
		key = v.ClientId + "|" + v.Reason
	}
	if last, ok := self.handshakes[key]; ok && now-last < 60 {
		return
	}
	if len(self.handshakes) > 10000 {
		self.handshakes = make(map[string]int64)
	}
	self.handshakes[key] = now

	self.rejections = append([]Rejection{{
		Time: now, Remote: remote, ClientId: v.ClientId,
		Reason: v.Reason, Refused: refused,
	}}, self.rejections...)
	if len(self.rejections) > maxRejections {
		self.rejections = self.rejections[:maxRejections]
	}
}

// ErrBlocked is returned by CheckAgent for blocked agents.
var ErrBlocked = errors.New("agent is blocked")

// CheckAgent is called by the frontend for every decrypted message:
// it refuses blocked agents (in every mode), refuses connections
// whose certificate belongs to another agent (Enforce), and records
// what the agent presented for the readiness view.
func (self *Service) CheckAgent(req *http.Request, source, org_id string) error {
	base := utils.ClientIdFromSource(source)
	if self.IsBlocked(base) {
		return ErrBlocked
	}

	kind := KindNone
	if req != nil && req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		leaf := req.TLS.PeerCertificates[0]
		kind = KindOther
		if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			if crypto_utils.ClientIDFromPublicKey(pub) == base {
				kind = KindOwn
			} else if v := self.classify(req.TLS.PeerCertificates[:1]); v.Kind == KindLegacy {
				kind = KindLegacy
			}
		}
	}

	remote := ""
	if req != nil {
		remote = req.RemoteAddr
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
	}

	self.mu.Lock()
	mode := self.effectiveModeLocked()
	if mode != ModeOff {
		self.seen[base] = &seenAgent{
			OrgId: org_id, Kind: kind, LastSeen: self.now().Unix(), Remote: remote,
		}
	}
	self.mu.Unlock()

	if mode == ModeEnforce && kind == KindOther {
		return errRefused
	}
	return nil
}

// keyCache remembers which agent keys this server enrolled, so the
// handshake rarely touches the datastore.
type keyCache struct {
	mu      sync.Mutex
	entries map[string]keyCacheEntry
	lookup  func(client_id string) (*rsa.PublicKey, bool)
	now     func() time.Time
}

type keyCacheEntry struct {
	key     *rsa.PublicKey
	expires time.Time
}

const (
	positiveTTL = time.Hour
	negativeTTL = 30 * time.Second
	maxKeyCache = 200000
)

func newKeyCache(lookup func(string) (*rsa.PublicKey, bool)) *keyCache {
	return &keyCache{
		entries: make(map[string]keyCacheEntry),
		lookup:  lookup,
		now:     time.Now,
	}
}

func (self *keyCache) known(client_id string, pub *rsa.PublicKey) bool {
	now := self.now()
	self.mu.Lock()
	entry, ok := self.entries[client_id]
	self.mu.Unlock()

	if !ok || now.After(entry.expires) {
		key, found := self.lookup(client_id)
		entry = keyCacheEntry{key: key, expires: now.Add(negativeTTL)}
		if found {
			entry.expires = now.Add(positiveTTL)
		}
		self.mu.Lock()
		if len(self.entries) > maxKeyCache {
			self.entries = make(map[string]keyCacheEntry)
		}
		self.entries[client_id] = entry
		self.mu.Unlock()
	}
	return entry.key != nil && entry.key.E == pub.E && entry.key.N.Cmp(pub.N) == 0
}

// lookupEnrolledKey finds the enrolled public key of an agent in any
// org.
func (self *Service) lookupEnrolledKey(client_id string) (*rsa.PublicKey, bool) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, false
	}
	for _, org := range org_manager.ListOrgs() {
		org_config, err := org_manager.GetOrgConfig(org.Id)
		if err != nil {
			continue
		}
		db, err := datastore.GetDB(org_config)
		if err != nil {
			continue
		}
		pem := &crypto_proto.PublicKey{}
		path := paths.NewClientPathManager(
			utils.ClientIdFromConfigObj(client_id, org_config)).Key()
		if err := db.GetSubject(org_config, path, pem); err != nil || len(pem.Pem) == 0 {
			continue
		}
		key, err := crypto_utils.PemToPublicKey(pem.Pem)
		if err == nil {
			return key, true
		}
	}
	return nil, false
}
