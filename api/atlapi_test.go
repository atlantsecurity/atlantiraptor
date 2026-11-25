package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	yamlv3 "gopkg.in/yaml.v3"
	"math/big"
	"testing"
	"time"

	"github.com/Velocidex/ordereddict"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestAPIRateLimit(t *testing.T) {
	k := APIKey{ID: "ratetest00000001", RateLimit: 5}
	now := time.Unix(1000, 0)
	allowed := 0
	for i := 0; i < 100; i++ {
		if allowRequest(k, now) {
			allowed++
		}
	}
	if allowed != defaultKeyBurst {
		t.Fatalf("burst: allowed %d, want %d", allowed, defaultKeyBurst)
	}
	// One second later, five more.
	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < 100; i++ {
		if allowRequest(k, now) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("refill: allowed %d, want 5", allowed)
	}
}

func TestVerifyAPIKeyRejectsMalformed(t *testing.T) {
	root := &config_proto.Config{Frontend: &config_proto.FrontendConfig{PrivateKey: "k"}}
	for _, tok := range []string{"", "abc", "atl_", "atl_short_secret", "atl_0123456789abcdef", "Bearer atl_x"} {
		if _, err := VerifyAPIKey(root, tok, time.Now()); err == nil {
			t.Errorf("token %q accepted", tok)
		}
	}
	if _, err := VerifyAPIKey(&config_proto.Config{}, "atl_0123456789abcdef_secret", time.Now()); err == nil {
		t.Error("accepted without a server key")
	}
}

func TestHashSecretDependsOnPepper(t *testing.T) {
	a := hashSecret([]byte("one"), "s")
	b := hashSecret([]byte("two"), "s")
	if a == b || a != hashSecret([]byte("one"), "s") {
		t.Fatal("hash must be deterministic and pepper-dependent")
	}
}

func TestValidateKeyRoles(t *testing.T) {
	for _, bad := range [][]string{{}, {"administrator"}, {"org_admin"}, {"artifact_writer"}, {"reader", "administrator"}} {
		if _, err := validateKeyRoles(bad); err == nil {
			t.Errorf("roles %v accepted", bad)
		}
	}
	got, err := validateKeyRoles([]string{"responder", "responder", "reader"})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestTargetValidate(t *testing.T) {
	cases := []struct {
		t  apiTarget
		ok bool
	}{
		{apiTarget{ClientId: "C.f614264ea30165fa"}, true},
		{apiTarget{ClientId: "C.bad"}, false},
		{apiTarget{All: true}, true},
		{apiTarget{OS: "WINDOWS"}, true},
		{apiTarget{OS: "windows; drop"}, false},
		{apiTarget{Labels: []string{"prod"}}, true},
		{apiTarget{Labels: []string{"bad\"label"}}, false},
		{apiTarget{}, false},
		{apiTarget{All: true, OS: "LINUX"}, false},
	}
	for _, c := range cases {
		if got := c.t.validate() == ""; got != c.ok {
			t.Errorf("%+v: ok=%v want %v", c.t, got, c.ok)
		}
	}
}

func TestBuildSpec(t *testing.T) {
	if _, msg := buildSpec([]string{"Windows.System.Pslist"}, artifactParams{"Other.Artifact": {"a": "b"}}); msg == "" {
		t.Error("params for an unlaunched artifact accepted")
	}
	if _, msg := buildSpec([]string{"bad name;"}, nil); msg == "" {
		t.Error("bad artifact name accepted")
	}
	if _, msg := buildSpec([]string{"A.B"}, artifactParams{"A.B": {"bad key": "x"}}); msg == "" {
		t.Error("bad parameter name accepted")
	}
	spec, msg := buildSpec([]string{"A.B"}, artifactParams{"A.B": {"Glob": "C:/x"}})
	if msg != "" || spec.Len() != 1 {
		t.Fatalf("spec %v %v", spec, msg)
	}
}

func TestRowTimestamp(t *testing.T) {
	if rowTimestamp(ordereddict.NewDict().Set("_ts", int64(42))) != 42 {
		t.Error("int64")
	}
	if rowTimestamp(ordereddict.NewDict().Set("_ts", float64(43))) != 43 {
		t.Error("float")
	}
	if rowTimestamp(ordereddict.NewDict().Set("timestamp", "2026-01-01T00:00:00Z")) != 1767225600 {
		t.Error("rfc3339")
	}
}

func TestActionCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range apiActions {
		if seen[a.ID] {
			t.Errorf("duplicate action %s", a.ID)
		}
		seen[a.ID] = true
		if len(a.Artifacts) == 0 || (a.Kind != "response" && a.Kind != "triage") {
			t.Errorf("action %s malformed", a.ID)
		}
		if a.Kind == "triage" && a.Live {
			t.Errorf("triage action %s marked live", a.ID)
		}
	}
	if findAPIAction("kill") == nil || findAPIAction("nope") != nil {
		t.Error("findAPIAction")
	}
}

func TestAuthFailureLimit(t *testing.T) {
	now := time.Unix(5000, 0)
	ip := "198.51.100.9"
	for i := 0; i < authFailBurst; i++ {
		if authBlocked(ip, now) {
			t.Fatalf("blocked after %d failures", i)
		}
		authFailed(ip, now)
	}
	if !authBlocked(ip, now) {
		t.Fatal("not blocked after the burst")
	}
	if authBlocked(ip, now.Add(4*time.Second)) {
		t.Fatal("still blocked after refill")
	}
	if authBlocked("198.51.100.10", now) {
		t.Fatal("other addresses must not be blocked")
	}
}

func TestValidateIOC(t *testing.T) {
	good := [][2]string{{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"md5", "d41d8cd98f00b204e9800998ecf8427e"}, {"ip", "203.0.113.7"}, {"ip", "2001:db8::1"},
		{"domain", "evil.example"}, {"domain", "*.evil.example"}, {"path", `C:\Users\x\a.exe`}}
	for _, g := range good {
		if msg := validateIOC(g[0], g[1]); msg != "" {
			t.Errorf("%v rejected: %s", g, msg)
		}
	}
	bad := [][2]string{{"sha256", "xyz"}, {"ip", "1.2.3"}, {"domain", "a|.*"}, {"domain", "("}, {"path", "a\nb"}}
	for _, b := range bad {
		if validateIOC(b[0], b[1]) == "" {
			t.Errorf("%v accepted", b)
		}
	}
}

func TestAuthFailureTableIsCapped(t *testing.T) {
	authFailMu.Lock()
	authFails = map[string]*bucket{}
	authFailMu.Unlock()
	now := time.Unix(9000, 0)
	for i := 0; i < maxAuthFailEntries+500; i++ {
		authFailed(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), now)
	}
	authFailMu.Lock()
	n := len(authFails)
	authFails = map[string]*bucket{}
	authFailMu.Unlock()
	if n > maxAuthFailEntries {
		t.Fatalf("table grew to %d", n)
	}
}

func TestConnectionInfo(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "VelociraptorServer"},
		DNSNames: []string{"VelociraptorServer"}, NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cfg := &config_proto.Config{
		GUI:      &config_proto.GUIConfig{BindAddress: "127.0.0.1", BindPort: 8889},
		Frontend: &config_proto.FrontendConfig{Certificate: certPEM},
		Client:   &config_proto.ClientConfig{CaCertificate: certPEM},
	}
	info := connectionInfo(cfg)
	if info.CertName != "VelociraptorServer" || info.Port != 8889 || !info.Loopback || !info.HasCA {
		t.Fatalf("unexpected %+v", info)
	}
	if connectionInfo(&config_proto.Config{}).CertName != "" {
		t.Fatal("empty config should give no name")
	}
}

func TestOpenAPISpecParsesAndCoversRoutes(t *testing.T) {
	var doc struct {
		Paths map[string]interface{} `yaml:"paths"`
	}
	if err := yamlv3.Unmarshal([]byte(atlOpenAPISpec), &doc); err != nil {
		t.Fatalf("spec is not valid YAML: %v", err)
	}
	for _, p := range []string{"/actions/{id}/run", "/rapid-hunts", "/rapid-hunts/{hunt_id}", "/approvals",
		"/approvals/{hunt_id}/approve", "/clients/{client_id}/flows/{flow_id}/uploads/{index}", "/query", "/stats"} {
		if _, ok := doc.Paths[p]; !ok {
			t.Errorf("spec is missing %s", p)
		}
	}
}

func TestRapidIndicatorProblem(t *testing.T) {
	for _, ok := range []string{"evil.example", "https://evil.example/x?y=1", "203.0.113.7", "2001:db8::1", "evil.example/path"} {
		if msg := rapidIndicatorProblem(ok); msg != "" {
			t.Errorf("%q rejected: %s", ok, msg)
		}
	}
	for _, bad := range []string{"", "two words", "a|.*", "http://", "nodot"} {
		if rapidIndicatorProblem(bad) == "" {
			t.Errorf("%q accepted", bad)
		}
	}
}
