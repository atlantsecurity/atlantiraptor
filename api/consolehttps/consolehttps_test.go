package consolehttps

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

type testPKI struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   string
	roots   *x509.CertPool
	leafPEM string
	keyPEM  string
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newPKI(t *testing.T, names []string, notAfter time.Time) *testPKI {
	t.Helper()
	p := &testPKI{}
	var err error
	p.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.caCert, _ = x509.ParseCertificate(der)
	p.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.caCert)

	p.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &p.leafKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.leaf, _ = x509.ParseCertificate(der)
	p.leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kder, _ := x509.MarshalPKCS8PrivateKey(p.leafKey)
	p.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	return p
}

func (p *testPKI) trust(t *testing.T) {
	old := trustRoots
	trustRoots = func() (*x509.CertPool, error) { return p.roots, nil }
	t.Cleanup(func() { trustRoots = old })
}

func TestNormalizeHostname(t *testing.T) {
	for in, want := range map[string]string{
		"Console.Example.com":         "console.example.com",
		" console.example.com. ":      "console.example.com",
		"https://console.example.com": "console.example.com",
		"10.0.0.5":                    "10.0.0.5",
	} {
		got, err := NormalizeHostname(in, true)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "console.example.com:8889", "console.example.com/app", "*.example.com",
		"localhost", "under_score.example.com", "no-tld"} {
		if _, err := NormalizeHostname(bad, true); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NormalizeHostname("10.0.0.5", false); err == nil {
		t.Error("IP accepted for Let's Encrypt")
	}
}

func TestValidateSettings(t *testing.T) {
	reserved := []ReservedPort{{Port: 8889, Use: "the console"}, {Port: 8000, Use: "clients"}}
	s, warn, err := ValidateSettings(Settings{Hostname: "console.example.com", Mode: ModeLetsEncrypt}, reserved)
	if err != nil || s.Port != 443 || len(warn) != 0 || !s.Enabled {
		t.Fatalf("got %+v %v %v", s, warn, err)
	}
	if _, _, err := ValidateSettings(Settings{Hostname: "c.example.com", Mode: ModeLetsEncrypt, Port: 8000}, reserved); err == nil ||
		!strings.Contains(err.Error(), "clients") {
		t.Errorf("reserved port accepted: %v", err)
	}
	if _, warn, err := ValidateSettings(Settings{Hostname: "c.example.com", Mode: ModeLetsEncrypt, Port: 8443}, reserved); err != nil || len(warn) != 1 {
		t.Errorf("non-443 Let's Encrypt should warn: %v %v", warn, err)
	}
	if _, _, err := ValidateSettings(Settings{Hostname: "c.example.com", Mode: ModeCertificate, Port: 80, RedirectHTTP: true}, reserved); err == nil {
		t.Error("port 80 with redirect accepted")
	}
	if _, _, err := ValidateSettings(Settings{Hostname: "c.example.com", Mode: "magic"}, reserved); err == nil {
		t.Error("unknown mode accepted")
	}
	if _, _, err := ValidateSettings(Settings{Hostname: "c.example.com", Mode: ModeCertificate, BindAddress: "eth0"}, reserved); err == nil {
		t.Error("bad bind address accepted")
	}
}

func TestParseUploadAndCheck(t *testing.T) {
	p := newPKI(t, []string{"console.example.com"}, time.Now().Add(90*24*time.Hour))
	p.trust(t)

	certPEM, keyPEM, err := ParseUpload(Upload{CertPEM: p.leafPEM, KeyPEM: p.keyPEM})
	if err != nil || len(keyPEM) == 0 {
		t.Fatal(err)
	}
	info, warn, err := CheckCertificate(certPEM, "console.example.com")
	if err != nil || len(warn) != 0 || !info.Trusted {
		t.Fatalf("%+v %v %v", info, warn, err)
	}
	if _, _, err := CheckCertificate(certPEM, "other.example.com"); err == nil {
		t.Error("wrong host accepted")
	}

	// Mismatched key.
	other := newPKI(t, []string{"console.example.com"}, time.Now().Add(90*24*time.Hour))
	if _, _, err := ParseUpload(Upload{CertPEM: p.leafPEM, KeyPEM: other.keyPEM}); err == nil {
		t.Error("mismatched key accepted")
	}

	// Untrusted issuer warns but doesn't fail.
	_, warn, err = CheckCertificate(other.leafPEM, "console.example.com")
	if err != nil || len(warn) == 0 {
		t.Errorf("untrusted: %v %v", warn, err)
	}

	// PFX with chain.
	pfx, err := pkcs12.Encode(rand.Reader, p.leafKey, p.leaf, []*x509.Certificate{p.caCert}, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pfx)
	certPEM, _, err = ParseUpload(Upload{PFXBase64: b64, PFXPassword: "pw"})
	if err != nil || strings.Count(certPEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("pfx: %v", err)
	}
	if _, _, err := ParseUpload(Upload{PFXBase64: b64, PFXPassword: "nope"}); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("wrong pfx password: %v", err)
	}
}

func TestExpiredAndExpiring(t *testing.T) {
	p := newPKI(t, []string{"console.example.com"}, time.Now().Add(10*24*time.Hour))
	p.trust(t)
	_, warn, err := CheckCertificate(p.leafPEM, "console.example.com")
	if err != nil || len(warn) != 1 || !strings.Contains(warn[0], "expires") {
		t.Errorf("expiring: %v %v", warn, err)
	}
	old := Now
	Now = func() time.Time { return time.Now().Add(20 * 24 * time.Hour) }
	defer func() { Now = old }()
	if _, _, err := CheckCertificate(p.leafPEM, "console.example.com"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired accepted: %v", err)
	}
}

func testConfig() *config_proto.Config {
	c := config.GetDefaultConfig()
	c.Datastore.Implementation = "Test"
	c.Frontend.PrivateKey = "test-key"
	if c.Security == nil {
		c.Security = &config_proto.Security{}
	}
	return c
}

// A manager whose listeners go to loopback on a free port.
func testManager(t *testing.T) (*Manager, *config_proto.Config, *[]string) {
	t.Helper()
	m := NewManager()
	var addrs []string
	m.listen = func(network, addr string) (net.Listener, error) {
		if strings.HasSuffix(addr, ":80") {
			return net.Listen(network, "127.0.0.1:0")
		}
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			addrs = append(addrs, ln.Addr().String())
		}
		return ln, err
	}
	cfg := testConfig()
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	t.Cleanup(func() { cancel(); wg.Wait() })
	m.Start(ctx, wg, cfg, Options{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("console")) }),
		Reserved:    []ReservedPort{{Port: 8889, Use: "the console"}},
		RecoveryURL: "https://server:8889/app/index.html",
	})
	return m, cfg, &addrs
}

func get(t *testing.T, addr string, roots *x509.CertPool) (string, error) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "console.example.com"}}}
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), nil
}

func TestApplyConfirmAndRollback(t *testing.T) {
	p := newPKI(t, []string{"console.example.com"}, time.Now().Add(90*24*time.Hour))
	p.trust(t)
	m, cfg, addrs := testManager(t)
	ctx := context.Background()
	settings := Settings{Hostname: "console.example.com", Mode: ModeCertificate}
	up := Upload{CertPEM: p.leafPEM, KeyPEM: p.keyPEM}

	v, _, err := m.Apply(ctx, "admin", settings, up, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.Serving != "pending" || v.Pending == nil || v.URL != "https://console.example.com/app/index.html" {
		t.Fatalf("view %+v", v)
	}
	if body, err := get(t, (*addrs)[0], p.roots); err != nil || body != "console" {
		t.Fatalf("serving: %q %v", body, err)
	}

	// Confirm persists; a new manager on the same store picks it up.
	if _, err := m.Confirm(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	s, key, err := load(ctx, cfg)
	if err != nil || !s.Enabled || len(key) == 0 || s.Hostname != "console.example.com" {
		t.Fatalf("stored %+v %v", s, err)
	}

	// A trial that isn't confirmed rolls back to the confirmed one.
	PendingTimeout = 200 * time.Millisecond
	defer func() { PendingTimeout = 10 * time.Minute }()
	settings2 := settings
	settings2.Port = 8443
	if _, _, err := m.Apply(ctx, "admin", settings2, Upload{}, true, false); err != nil {
		t.Fatal(err)
	}
	if m.Status().Active.Port != 443 || m.Status().Pending.Settings.Port != 8443 {
		t.Fatal("pending not separate from active")
	}
	deadline := time.Now().Add(3 * time.Second)
	for m.Status().Pending != nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	v = m.Status()
	if v.Pending != nil || v.Serving != "active" || v.URL != "https://console.example.com/app/index.html" {
		t.Fatalf("did not roll back: %+v", v)
	}
	if _, err := get(t, (*addrs)[len(*addrs)-1], p.roots); err != nil {
		t.Fatalf("rolled-back listener not serving: %v", err)
	}

	// Disable stops serving and stores "off".
	if _, err := m.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if m.Status().Serving != "" {
		t.Fatal("still serving after disable")
	}
	s, _, _ = load(ctx, cfg)
	if s.Enabled {
		t.Fatal("disable not stored")
	}
}

func TestUntrustedNeedsConfirmation(t *testing.T) {
	p := newPKI(t, []string{"console.example.com"}, time.Now().Add(90*24*time.Hour))
	m, _, _ := testManager(t) // system roots: the test CA is unknown
	_, warn, err := m.Apply(context.Background(), "admin",
		Settings{Hostname: "console.example.com", Mode: ModeCertificate},
		Upload{CertPEM: p.leafPEM, KeyPEM: p.keyPEM}, false, false)
	ae, ok := err.(*ApplyError)
	if !ok || ae.Code != "needs_confirmation" || len(warn) == 0 {
		t.Fatalf("got %v %v", err, warn)
	}
	if m.Status().Serving != "" {
		t.Fatal("started without confirmation")
	}
	if _, _, err := m.Apply(context.Background(), "admin",
		Settings{Hostname: "console.example.com", Mode: ModeCertificate},
		Upload{CertPEM: p.leafPEM, KeyPEM: p.keyPEM}, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Revert(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if m.Status().Serving != "" {
		t.Fatal("revert left the trial running")
	}
}

func TestListenFailureKeepsPrevious(t *testing.T) {
	p := newPKI(t, []string{"console.example.com"}, time.Now().Add(90*24*time.Hour))
	p.trust(t)
	m, _, addrs := testManager(t)
	ctx := context.Background()
	if _, _, err := m.Apply(ctx, "admin", Settings{Hostname: "console.example.com", Mode: ModeCertificate},
		Upload{CertPEM: p.leafPEM, KeyPEM: p.keyPEM}, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	ok := m.listen
	m.listen = func(network, addr string) (net.Listener, error) {
		if strings.HasSuffix(addr, ":9443") {
			return nil, &net.OpError{Op: "listen", Err: errString("bind: address already in use")}
		}
		return ok(network, addr)
	}
	_, _, err := m.Apply(ctx, "admin", Settings{Hostname: "console.example.com", Mode: ModeCertificate, Port: 9443},
		Upload{}, true, false)
	if err == nil || !strings.Contains(err.Error(), "already uses port 9443") {
		t.Fatalf("got %v", err)
	}
	v := m.Status()
	if v.Serving != "active" || v.Pending != nil {
		t.Fatalf("previous not restored: %+v", v)
	}
	if _, err := get(t, (*addrs)[len(*addrs)-1], p.roots); err != nil {
		t.Fatalf("restored listener not serving: %v", err)
	}
}

func TestRedirectUsesConfiguredHost(t *testing.T) {
	h := redirectHandler("https://console.example.com")
	req, _ := http.NewRequest("GET", "http://evil.example.net/app/index.html?x=1", nil)
	req.Host = "evil.example.net"
	rec := &recorder{header: http.Header{}}
	h.ServeHTTP(rec, req)
	if loc := rec.header.Get("Location"); loc != "https://console.example.com/app/index.html?x=1" {
		t.Fatalf("redirect to %q", loc)
	}
}

func TestUnavailable(t *testing.T) {
	m := NewManager()
	m.Start(context.Background(), nil, testConfig(), Options{Unavailable: "minion"})
	if _, _, err := m.Apply(context.Background(), "a", Settings{}, Upload{}, false, false); err == nil {
		t.Fatal("apply on unavailable server")
	}
	if v := m.Status(); v.Available || v.Unavailable != "minion" {
		t.Fatalf("%+v", v)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

type recorder struct {
	header http.Header
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }

func TestLetsEncryptFailureIsReported(t *testing.T) {
	m, _, _ := testManager(t)
	m.acmeClient = &acme.Client{DirectoryURL: "http://127.0.0.1:1/directory"}
	v, _, err := m.Apply(context.Background(), "admin",
		Settings{Hostname: "console.example.com", Mode: ModeLetsEncrypt}, Upload{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.Cert.Status != "issuing" {
		t.Fatalf("status %q", v.Cert.Status)
	}
	deadline := time.Now().Add(10 * time.Second)
	for m.Status().Cert.Status == "issuing" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := m.Status().Cert; st.Status != "failed" || st.Error == "" {
		t.Fatalf("got %+v", st)
	}
	if _, err := m.Confirm(context.Background(), "admin"); err == nil {
		t.Fatal("confirmed without a certificate")
	}
}
