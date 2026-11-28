package agentmtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/crypto"
	crypto_utils "www.velocidex.com/golang/velociraptor/crypto/utils"
	"www.velocidex.com/golang/velociraptor/vql/networking"
)

type fixture struct {
	t       *testing.T
	config  *config_proto.Config
	service *Service
	// Enrolled agent keys by client ID.
	enrolled map[string]*rsa.PublicKey
	server   *tls.Certificate
}

func newFixture(t *testing.T) *fixture {
	ca, err := crypto.GenerateCACert(2048)
	if err != nil {
		t.Fatal(err)
	}
	config_obj := &config_proto.Config{
		Client: &config_proto.ClientConfig{
			CaCertificate: ca.Cert,
		},
		CA:        &config_proto.CAConfig{PrivateKey: ca.PrivateKey},
		Datastore: &config_proto.DatastoreConfig{Location: t.TempDir()},
		Frontend:  &config_proto.FrontendConfig{},
	}
	bundle, err := crypto.GenerateServerCert(config_obj, "VelociraptorServer")
	if err != nil {
		t.Fatal(err)
	}
	server_cert, err := tls.X509KeyPair([]byte(bundle.Cert), []byte(bundle.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		t:        t,
		config:   config_obj,
		enrolled: make(map[string]*rsa.PublicKey),
		server:   &server_cert,
	}
	f.service = f.newService()
	return f
}

func (self *fixture) newService() *Service {
	s := newService(self.config)
	s.keys = newKeyCache(func(id string) (*rsa.PublicKey, bool) {
		k, ok := self.enrolled[id]
		return k, ok
	})
	s.load()
	s.SetFrontendInfo("")
	return s
}

func (self *fixture) set(mode string, enrollment, legacy bool) {
	self.service.mu.Lock()
	self.service.settings = Settings{Mode: mode, AllowEnrollment: enrollment, AllowLegacy: legacy}
	self.service.mu.Unlock()
}

type agent struct {
	key *rsa.PrivateKey
	id  string
}

func newAgent(t *testing.T) *agent {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &agent{key: key, id: crypto_utils.ClientIDFromPublicKey(&key.PublicKey)}
}

func (self *fixture) enroll(a *agent) {
	self.enrolled[a.id] = &a.key.PublicKey
}

func (self *fixture) deployment() (*x509.Certificate, *rsa.PrivateKey) {
	cert_pem, key_pem := self.service.DeploymentCertificate()
	cert, err := crypto_utils.ParseX509CertFromPemStr([]byte(cert_pem))
	if err != nil {
		self.t.Fatal(err)
	}
	key, err := crypto_utils.ParseRsaPrivateKeyFromPemStr([]byte(key_pem))
	if err != nil {
		self.t.Fatal(err)
	}
	return cert, key
}

func parseChain(t *testing.T, c *tls.Certificate) []*x509.Certificate {
	var result []*x509.Certificate
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, cert)
	}
	return result
}

func (self *fixture) selfSigned(a *agent) []*x509.Certificate {
	c, err := networking.BuildAgentCertificate(a.key, a.id, nil, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return parseChain(self.t, c)
}

func (self *fixture) chained(a *agent) []*x509.Certificate {
	parent, parent_key := self.deployment()
	c, err := networking.BuildAgentCertificate(a.key, a.id, parent, parent_key)
	if err != nil {
		self.t.Fatal(err)
	}
	return parseChain(self.t, c)
}

func TestDeploymentCertificateIsIssuedAndKept(t *testing.T) {
	f := newFixture(t)
	cert, _ := f.deployment()
	if cert.Subject.CommonName != DeploymentCommonName {
		t.Fatalf("common name %q", cert.Subject.CommonName)
	}
	ca, _ := crypto_utils.ParseX509CertFromPemStr([]byte(f.config.Client.CaCertificate))
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("not signed by the CA: %v", err)
	}

	// A restart keeps the same certificate.
	again := f.newService()
	a, _ := again.DeploymentCertificate()
	b, _ := f.service.DeploymentCertificate()
	if a != b {
		t.Fatal("deployment certificate changed on restart")
	}
}

func TestWizardClientCertificateBecomesDeploymentCertificate(t *testing.T) {
	f := newFixture(t)
	bundle, err := crypto.GenerateServerCert(f.config, "Client")
	if err != nil {
		t.Fatal(err)
	}
	f.config.Client.Crypto = &config_proto.CryptoConfig{
		ClientCertificate:           bundle.Cert,
		ClientCertificatePrivateKey: bundle.PrivateKey,
	}
	f.config.Datastore.Location = t.TempDir()
	s := f.newService()
	cert, _ := s.DeploymentCertificate()
	if cert != bundle.Cert {
		t.Fatal("the configuration's client certificate should be the deployment certificate")
	}
	if !s.Status(context.Background()).Deployment.FromConfig {
		t.Fatal("expected from_config")
	}
}

func TestClassify(t *testing.T) {
	f := newFixture(t)
	enrolled := newAgent(t)
	f.enroll(enrolled)
	fresh := newAgent(t)
	parent, _ := f.deployment()

	f.set(ModeEnforce, true, true)

	cases := []struct {
		name  string
		certs []*x509.Certificate
		kind  string
		ok    bool
	}{
		{"no certificate", nil, KindNone, false},
		{"enrolled, self-signed", f.selfSigned(enrolled), KindOwn, true},
		{"enrolled, chained", f.chained(enrolled), KindOwn, true},
		{"new agent, chained", f.chained(fresh), KindNew, true},
		{"new agent, self-signed", f.selfSigned(fresh), KindOther, false},
		{"older agent, deployment certificate only", []*x509.Certificate{parent}, KindLegacy, true},
	}
	for _, c := range cases {
		v := f.service.classify(c.certs)
		if v.Kind != c.kind || v.OK != c.ok {
			t.Errorf("%s: got %+v, want kind %v ok %v", c.name, v, c.kind, c.ok)
		}
	}

	// Pausing enrollment and refusing older agents.
	f.set(ModeEnforce, false, false)
	if v := f.service.classify(f.chained(fresh)); v.OK {
		t.Errorf("new agent accepted with enrollment paused: %+v", v)
	}
	if v := f.service.classify([]*x509.Certificate{parent}); v.OK {
		t.Errorf("older agent accepted: %+v", v)
	}
	if v := f.service.classify(f.selfSigned(enrolled)); !v.OK {
		t.Errorf("enrolled agent refused: %+v", v)
	}
}

func TestForgedChainsAreRefused(t *testing.T) {
	f := newFixture(t)
	f.set(ModeEnforce, true, true)
	fresh := newAgent(t)

	// Signed by a certificate from another CA that claims the same
	// serial number as our deployment certificate.
	other := newFixture(t)
	other_parent, other_key := other.deployment()
	c, err := networking.BuildAgentCertificate(fresh.key, fresh.id, other_parent, other_key)
	if err != nil {
		t.Fatal(err)
	}
	if v := f.service.classify(parseChain(t, c)); v.OK {
		t.Fatalf("foreign deployment certificate accepted: %+v", v)
	}

	// Our deployment certificate attached, but the leaf signed by the
	// attacker's own key.
	parent, _ := f.deployment()
	attacker := newAgent(t)
	c, err = networking.BuildAgentCertificate(fresh.key, fresh.id, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = attacker
	chain := append(parseChain(t, c), parent)
	if v := f.service.classify(chain); v.OK {
		t.Fatalf("leaf not signed by the deployment certificate accepted: %+v", v)
	}

	// Another CA-signed certificate (e.g. the server's own or an API
	// client's) is not a deployment certificate.
	bundle, err := crypto.GenerateServerCert(f.config, "admin")
	if err != nil {
		t.Fatal(err)
	}
	api_cert, _ := crypto_utils.ParseX509CertFromPemStr([]byte(bundle.Cert))
	if v := f.service.classify([]*x509.Certificate{api_cert}); v.OK {
		t.Fatalf("API certificate accepted: %+v", v)
	}
}

func TestRotationKeepsEnrolledAgents(t *testing.T) {
	f := newFixture(t)
	f.set(ModeEnforce, true, true)
	enrolled := newAgent(t)
	f.enroll(enrolled)
	old_parent, old_key := f.deployment()

	if _, err := f.service.RotateDeployment(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	new_parent, _ := f.deployment()
	if new_parent.SerialNumber.Cmp(old_parent.SerialNumber) == 0 {
		t.Fatal("rotation kept the serial")
	}

	if v := f.service.classify(f.selfSigned(enrolled)); !v.OK {
		t.Fatalf("enrolled agent refused after rotation: %+v", v)
	}
	// Chained with the old deployment certificate but enrolled: fine.
	c, _ := networking.BuildAgentCertificate(enrolled.key, enrolled.id, old_parent, old_key)
	if v := f.service.classify(parseChain(t, c)); !v.OK {
		t.Fatalf("enrolled agent with old chain refused: %+v", v)
	}

	// New agents need the new deployment certificate.
	fresh := newAgent(t)
	c, _ = networking.BuildAgentCertificate(fresh.key, fresh.id, old_parent, old_key)
	if v := f.service.classify(parseChain(t, c)); v.OK {
		t.Fatalf("new agent with the old deployment certificate accepted: %+v", v)
	}
	if v := f.service.classify(f.chained(fresh)); !v.OK {
		t.Fatalf("new agent with the new deployment certificate refused: %+v", v)
	}
	if v := f.service.classify([]*x509.Certificate{old_parent}); v.OK {
		t.Fatalf("older agent with the old deployment certificate accepted: %+v", v)
	}
}

func TestBlock(t *testing.T) {
	f := newFixture(t)
	f.set(ModeWarn, true, true)
	a := newAgent(t)
	f.enroll(a)

	if _, err := f.service.Block(context.Background(), a.id+"-O123", "O123", "laptop", "lost", "admin"); err != nil {
		t.Fatal(err)
	}
	if !f.service.IsBlocked(a.id) {
		t.Fatal("not blocked")
	}
	if v := f.service.classify(f.selfSigned(a)); v.OK {
		t.Fatalf("blocked agent accepted: %+v", v)
	}
	if err := f.service.CheckAgent(nil, a.id, ""); !errors.Is(err, ErrBlocked) {
		t.Fatalf("CheckAgent: %v", err)
	}

	// Survives a restart.
	if !f.newService().IsBlocked(a.id) {
		t.Fatal("block lost on restart")
	}

	if _, err := f.service.Unblock(context.Background(), a.id, "admin"); err != nil {
		t.Fatal(err)
	}
	if v := f.service.classify(f.selfSigned(a)); !v.OK {
		t.Fatalf("unblocked agent refused: %+v", v)
	}

	if _, err := f.service.Block(context.Background(), "server", "", "", "", "admin"); err == nil {
		t.Fatal("blocked a non-agent ID")
	}
}

func TestEnforceNeedsReadyAgents(t *testing.T) {
	f := newFixture(t)
	f.set(ModeWarn, true, true)

	ready := newAgent(t)
	f.enroll(ready)
	old := newAgent(t)
	f.enroll(old)

	req := func(certs []*x509.Certificate) *http.Request {
		r := httptest.NewRequest("POST", "/control", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
		return r
	}
	if err := f.service.CheckAgent(req(f.selfSigned(ready)), ready.id, "root"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.CheckAgent(req(nil), old.id, "root"); err != nil {
		t.Fatal(err)
	}

	status := f.service.Status(context.Background())
	if status.Counts.Own != 1 || status.Counts.None != 1 || status.WouldRefuse != 1 {
		t.Fatalf("counts %+v would refuse %v", status.Counts, status.WouldRefuse)
	}
	if len(status.NotReady) != 1 || status.NotReady[0].ClientId != old.id {
		t.Fatalf("not ready %+v", status.NotReady)
	}

	_, err := f.service.SetSettings(context.Background(),
		Settings{Mode: ModeEnforce, AllowEnrollment: true, AllowLegacy: true}, "admin", false)
	var not_ready ErrNotReady
	if !errors.As(err, &not_ready) || not_ready.Count != 1 {
		t.Fatalf("expected ErrNotReady, got %v", err)
	}
	if _, err := f.service.SetSettings(context.Background(),
		Settings{Mode: ModeEnforce, AllowEnrollment: true, AllowLegacy: true}, "admin", true); err != nil {
		t.Fatal(err)
	}
	if f.service.EffectiveMode() != ModeEnforce {
		t.Fatal("mode not saved")
	}

	// Another agent's certificate on this agent's messages.
	if err := f.service.CheckAgent(req(f.selfSigned(ready)), old.id, "root"); err == nil {
		t.Fatal("mismatched certificate accepted in enforce mode")
	}
}

func TestUnavailableForcesOff(t *testing.T) {
	f := newFixture(t)
	f.set(ModeEnforce, true, true)
	f.service.SetFrontendInfo("the console shares the agent port")
	if f.service.EffectiveMode() != ModeOff {
		t.Fatal("expected off")
	}
	if _, err := f.service.SetSettings(context.Background(),
		Settings{Mode: ModeEnforce}, "admin", true); err == nil {
		t.Fatal("enforce allowed while unavailable")
	}
	t.Setenv(DisableEnv, "1")
	g := newFixture(t)
	g.set(ModeEnforce, true, true)
	if g.service.EffectiveMode() != ModeOff {
		t.Fatal("env var should turn it off")
	}
}

func TestWithDeploymentCertDoesNotTouchServerConfig(t *testing.T) {
	f := newFixture(t)
	global_mu.Lock()
	saved := global
	global = f.service
	global_mu.Unlock()
	defer func() {
		global_mu.Lock()
		global = saved
		global_mu.Unlock()
	}()

	client := &config_proto.Config{Client: f.config.Client}
	out := WithDeploymentCert(f.config, client)
	cert, _ := f.service.DeploymentCertificate()
	if out.Client.Crypto.GetClientCertificate() != cert {
		t.Fatal("deployment certificate not added")
	}
	if f.config.Client.Crypto != nil {
		t.Fatal("the server configuration was modified")
	}
}

// End to end: a real TLS frontend and the agent's TLS configuration.
func TestHandshake(t *testing.T) {
	f := newFixture(t)
	enrolled := newAgent(t)
	f.enroll(enrolled)

	ca_pool := x509.NewCertPool()
	ca_pool.AppendCertsFromPEM([]byte(f.config.Client.CaCertificate))

	base := &tls.Config{Certificates: []tls.Certificate{*f.server}, MinVersion: tls.VersionTLS12}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := r.Header.Get("X-Agent")
		if err := f.service.CheckAgent(r, source, "root"); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = f.service.WrapTLSConfig(base)
	srv.StartTLS()
	defer srv.Close()

	cert_pem, key_pem := f.service.DeploymentCertificate()

	get := func(a *agent, with_deployment bool) error {
		client_config := &config_proto.ClientConfig{
			CaCertificate: f.config.Client.CaCertificate,
			Crypto:        &config_proto.CryptoConfig{},
		}
		if with_deployment {
			client_config.Crypto.ClientCertificate = cert_pem
			client_config.Crypto.ClientCertificatePrivateKey = key_pem
		}
		if a != nil {
			networking.SetAgentKey(a.key, a.id)
		} else {
			networking.SetAgentKey(nil, "")
		}
		defer networking.SetAgentKey(nil, "")

		tls_config, err := networking.GetTlsConfig(client_config, "")
		if err != nil {
			return err
		}
		tr := &http.Transport{TLSClientConfig: tls_config,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
		defer tr.CloseIdleConnections()
		r, _ := http.NewRequest("GET", srv.URL, nil)
		if a != nil {
			r.Header.Set("X-Agent", a.id)
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(r)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return errors.New(resp.Status)
		}
		return nil
	}

	// Off: nobody is asked for anything.
	f.set(ModeOff, true, true)
	if err := get(nil, false); err != nil {
		t.Fatalf("off: %v", err)
	}

	// Warn: everyone gets in, and we learn who presents what.
	f.set(ModeWarn, true, true)
	if err := get(nil, false); err != nil {
		t.Fatalf("warn, no certificate: %v", err)
	}
	if err := get(enrolled, false); err != nil {
		t.Fatalf("warn, enrolled: %v", err)
	}
	if f.service.seen[enrolled.id].Kind != KindOwn {
		t.Fatalf("enrolled agent seen as %v", f.service.seen[enrolled.id].Kind)
	}

	// Enforce.
	f.set(ModeEnforce, true, true)
	if err := get(nil, false); err == nil {
		t.Fatal("enforce: connection without a certificate accepted")
	}
	if err := get(enrolled, false); err != nil {
		t.Fatalf("enforce, enrolled agent: %v", err)
	}
	fresh := newAgent(t)
	if err := get(fresh, true); err != nil {
		t.Fatalf("enforce, new agent with deployment certificate: %v", err)
	}
	if err := get(newAgent(t), false); err == nil {
		t.Fatal("enforce: unknown agent without deployment certificate accepted")
	}
	// An older binary: no agent key registered, presents the
	// configured deployment certificate as is.
	if err := get(nil, true); err != nil {
		t.Fatalf("enforce, older agent: %v", err)
	}
	f.set(ModeEnforce, true, false)
	if err := get(nil, true); err == nil {
		t.Fatal("enforce: older agent accepted with allow_legacy off")
	}

	// Blocked agents are refused in the handshake.
	if _, err := f.service.Block(context.Background(), enrolled.id, "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := get(enrolled, false); err == nil {
		t.Fatal("blocked agent accepted")
	}

	if len(f.service.Status(context.Background()).Rejections) == 0 {
		t.Fatal("no rejections recorded")
	}
}
