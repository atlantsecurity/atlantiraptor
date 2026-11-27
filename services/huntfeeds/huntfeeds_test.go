package huntfeeds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "ATL-TEST-1234-5678-ABCD"

func art(name string) string {
	return "name: " + name + "\ntype: CLIENT\nsources:\n  - query: SELECT * FROM info()\n"
}

func testPack(id string, version int, artifacts ...string) Pack {
	var defs []string
	for _, a := range artifacts {
		defs = append(defs, art(a))
	}
	return Pack{ID: id, Name: "Pack " + id, Version: version,
		Published: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Artifacts: defs}
}

type fakeInstaller struct {
	mu   sync.Mutex
	have map[string]bool
	bad  map[string]bool
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{have: map[string]bool{}, bad: map[string]bool{}}
}

func (self *fakeInstaller) Install(def string) (string, error) {
	self.mu.Lock()
	defer self.mu.Unlock()
	name := artifactName(def)
	if self.bad[name] {
		return "", errors.New("does not compile")
	}
	self.have[name] = true
	return name, nil
}

func (self *fakeInstaller) Remove(name string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	delete(self.have, name)
}

func (self *fakeInstaller) names() []string {
	self.mu.Lock()
	defer self.mu.Unlock()
	var res []string
	for k := range self.have {
		res = append(res, k)
	}
	return res
}

// withKeys installs a fresh signing key as the compiled-in key.
func withKeys(t *testing.T) (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := feedPublicKeys
	feedPublicKeys = map[string]string{"test-key": base64.StdEncoding.EncodeToString(pub)}
	t.Cleanup(func() { feedPublicKeys = old })
	return "test-key", priv
}

func sign(t *testing.T, key_id string, priv ed25519.PrivateKey, m *Manifest) []byte {
	data, err := SignManifest(m, key_id, priv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func manifest(t *testing.T, now time.Time, packs ...Pack) *Manifest {
	m, err := BuildManifest(packs, IssueOptions{
		LicenceKey: testKey, LicenceID: "L-1", Customer: "Acme", Plan: "Premium",
		Expires: now.Add(365 * 24 * time.Hour), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBundleSignature(t *testing.T) {
	key_id, priv := withKeys(t)
	now := time.Now()
	m := manifest(t, now, testPack("p1", 1, "Atlant.Feed.A"))
	data := sign(t, key_id, priv, m)

	got, err := ParseBundle(data, publicKeys())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckFor(testKey, now); err != nil {
		t.Fatal(err)
	}
	if err := got.CheckFor("ATL-OTHER-KEY", now); err == nil {
		t.Error("accepted a feed issued for another key")
	}
	if got.Packs[0].Hunt.ExpiresHours != defaultHuntHour ||
		len(got.Packs[0].Hunt.Artifacts) != 1 {
		t.Errorf("hunt defaults not filled in: %+v", got.Packs[0].Hunt)
	}

	// Tampering with the payload breaks the signature.
	var b Bundle
	_ = json.Unmarshal(data, &b)
	payload, _ := base64.StdEncoding.DecodeString(b.Payload)
	tampered := strings.Replace(string(payload), "Acme", "Evil", 1)
	b.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))
	bad, _ := json.Marshal(b)
	if _, err := ParseBundle(bad, publicKeys()); err == nil {
		t.Error("accepted a tampered bundle")
	}

	// Another key, even with a valid signature, is not accepted.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseBundle(sign(t, key_id, other, m), publicKeys()); err == nil {
		t.Error("accepted a bundle signed with someone else's key")
	}
	if _, err := ParseBundle(sign(t, "unknown", priv, m), publicKeys()); err == nil {
		t.Error("accepted an unknown key id")
	}
	if _, err := ParseBundle(data, nil); !errors.Is(err, errNoKeys) {
		t.Errorf("no keys: got %v", err)
	}
}

func TestManifestRules(t *testing.T) {
	now := time.Now()
	for name, packs := range map[string][]Pack{
		"wrong prefix":    {testPack("p1", 1, "Windows.System.Pslist")},
		"bare prefix":     {testPack("p1", 1, "Atlant.Feed.")},
		"duplicate pack":  {testPack("p1", 1, "Atlant.Feed.A"), testPack("p1", 2, "Atlant.Feed.B")},
		"shared artifact": {testPack("p1", 1, "Atlant.Feed.A"), testPack("p2", 1, "Atlant.Feed.A")},
		"bad id":          {testPack("P 1", 1, "Atlant.Feed.A")},
		"no version":      {testPack("p1", 0, "Atlant.Feed.A")},
		"no artifacts":    {{ID: "p1", Name: "x", Version: 1}},
	} {
		if _, err := BuildManifest(packs, IssueOptions{LicenceKey: testKey,
			Expires: now.Add(time.Hour), Now: now}); err == nil {
			t.Errorf("%v: accepted", name)
		}
	}

	p := testPack("p1", 1, "Atlant.Feed.A")
	p.Hunt.Artifacts = []string{"Atlant.Feed.Other"}
	if _, err := BuildManifest([]Pack{p}, IssueOptions{LicenceKey: testKey,
		Expires: now.Add(time.Hour), Now: now}); err == nil {
		t.Error("accepted a hunt on an artifact outside the pack")
	}

	// The lease never runs past the end of the subscription.
	m, err := BuildManifest(nil, IssueOptions{LicenceKey: testKey,
		Expires: now.Add(48 * time.Hour), Lease: 30 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if m.ValidUntil.After(m.Licence.Expires) {
		t.Errorf("lease %v runs past expiry %v", m.ValidUntil, m.Licence.Expires)
	}
	if err := m.CheckFor(testKey, now.Add(49*time.Hour)); !errors.Is(err, errExpired) {
		t.Errorf("after expiry: %v", err)
	}

	m2 := manifest(t, now)
	if err := m2.CheckFor(testKey, m2.ValidUntil.Add(time.Second)); !errors.Is(err, errLeaseOver) {
		t.Errorf("after lease: %v", err)
	}
	if err := m2.CheckFor(testKey, now.Add(-3*24*time.Hour)); err == nil {
		t.Error("accepted a feed dated days in the future")
	}
}

// feedServer serves whatever the test sets.
type feedServer struct {
	mu     sync.Mutex
	status int
	body   []byte
	auth   string
	hits   int
}

func (self *feedServer) set(status int, body []byte) {
	self.mu.Lock()
	self.status, self.body = status, body
	self.mu.Unlock()
}

func (self *feedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.hits++
	self.auth = r.Header.Get("Authorization")
	w.WriteHeader(self.status)
	_, _ = w.Write(self.body)
}

func setup(t *testing.T) (*Feeds, *fakeInstaller, *feedServer, string, ed25519.PrivateKey, *time.Time) {
	key_id, priv := withKeys(t)
	fs := &feedServer{status: 500}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	testInsecure = true
	t.Cleanup(func() { testInsecure = false })
	t.Setenv(FeedURLEnv, srv.URL+"/v1/feed")

	inst := newFakeInstaller()
	f := newFeeds(nil, inst)
	f.state_path = filepath.Join(t.TempDir(), stateFileName)
	now := time.Now()
	f.now = func() time.Time { return now }
	return f, inst, fs, key_id, priv, &now
}

func TestSyncLifecycle(t *testing.T) {
	f, inst, fs, key_id, priv, now := setup(t)
	ctx := context.Background()

	if s := f.Status(); s.State != StateUnlicensed {
		t.Fatalf("state %v", s.State)
	}
	fs.set(200, sign(t, key_id, priv, manifest(t, *now,
		testPack("p1", 1, "Atlant.Feed.A"), testPack("p2", 1, "Atlant.Feed.B", "Atlant.Feed.C"))))
	if err := f.SetLicenceKey(testKey, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if fs.auth != "Bearer "+testKey {
		t.Errorf("sent %q", fs.auth)
	}
	s := f.Status()
	if s.State != StateActive || len(s.Packs) != 2 || s.NewCount != 2 || len(inst.names()) != 3 {
		t.Fatalf("after first sync: %+v installed %v", s, inst.names())
	}
	if strings.Contains(mustJSON(s), testKey) {
		t.Error("the status contains the licence key")
	}
	if s.Licence.Customer != "Acme" || s.MaskedKey != "ATL-…ABCD" {
		t.Errorf("licence %+v masked %v", s.Licence, s.MaskedKey)
	}

	// Three weeks on: p1 updated, p2 withdrawn, p3 new.
	*now = now.Add(21 * 24 * time.Hour)
	fs.set(200, sign(t, key_id, priv, manifest(t, *now,
		testPack("p1", 2, "Atlant.Feed.A"), testPack("p3", 1, "Atlant.Feed.D"))))
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	s = f.Status()
	fresh := map[string]string{}
	for _, p := range s.Packs {
		fresh[p.ID] = p.Fresh
	}
	if fresh["p1"] != "updated" || fresh["p3"] != "new" || len(fresh) != 2 {
		t.Errorf("fresh %v", fresh)
	}
	if got := strings.Join(sortedNames(inst), ","); got != "Atlant.Feed.A,Atlant.Feed.D" {
		t.Errorf("installed %v", got)
	}

	// An older feed (replayed) is refused and changes nothing.
	old := manifest(t, now.Add(-24*time.Hour), testPack("p9", 1, "Atlant.Feed.Z"))
	fs.set(200, sign(t, key_id, priv, old))
	if err := f.Sync(ctx); err == nil {
		t.Error("accepted an older feed")
	}
	if s := f.Status(); s.State != StateActive || len(s.Packs) != 2 || s.LastError == "" {
		t.Errorf("after replay: %v %v %v", s.State, len(s.Packs), s.LastError)
	}

	// The service is down: the packs stay while the lease lasts.
	fs.set(503, []byte(`{"message":"maintenance"}`))
	if err := f.Sync(ctx); err == nil {
		t.Error("no error from a 503")
	}
	if s := f.Status(); s.State != StateActive || !strings.Contains(s.LastError, "maintenance") {
		t.Errorf("after 503: %v %q", s.State, s.LastError)
	}

	// The lease runs out without a renewal: packs go.
	*now = now.Add(15 * 24 * time.Hour)
	f.enforceLease()
	if s := f.Status(); s.State != StatePending || len(inst.names()) != 0 || s.Message == "" {
		t.Errorf("after the lease: %v %v %q", s.State, inst.names(), s.Message)
	}

	// Renewal brings them back.
	fs.set(200, sign(t, key_id, priv, manifest(t, *now, testPack("p1", 2, "Atlant.Feed.A"))))
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if s := f.Status(); s.State != StateActive || len(inst.names()) != 1 {
		t.Errorf("after renewal: %v %v", s.State, inst.names())
	}

	// The subscription is not paid: the service says 402.
	fs.set(402, []byte(`{"message":"Your subscription ended on 1 December."}`))
	_ = f.Sync(ctx)
	s = f.Status()
	if s.State != StateExpired || len(inst.names()) != 0 || len(s.Packs) != 0 ||
		!strings.Contains(s.Message, "1 December") {
		t.Errorf("after 402: %v %v %q", s.State, inst.names(), s.Message)
	}

	// A revoked key: 401.
	fs.set(401, nil)
	_ = f.Sync(ctx)
	if s := f.Status(); s.State != StateInvalid {
		t.Errorf("after 401: %v", s.State)
	}

	// Removing the key.
	if err := f.SetLicenceKey("", "admin"); err != nil {
		t.Fatal(err)
	}
	if s := f.Status(); s.State != StateUnlicensed || s.HasKey {
		t.Errorf("after removing: %+v", s)
	}
}

func TestExpiredFeedFromService(t *testing.T) {
	f, inst, fs, key_id, priv, now := setup(t)
	_ = f.SetLicenceKey(testKey, "admin")
	fs.set(200, sign(t, key_id, priv, manifest(t, *now, testPack("p1", 1, "Atlant.Feed.A"))))
	if err := f.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A year later the service (wrongly) sends the old feed: it has expired.
	*now = now.Add(400 * 24 * time.Hour)
	_ = f.Sync(context.Background())
	if s := f.Status(); s.State != StateExpired || len(inst.names()) != 0 {
		t.Errorf("%v %v", s.State, inst.names())
	}
}

func TestBrokenPackIsSkipped(t *testing.T) {
	f, inst, fs, key_id, priv, now := setup(t)
	inst.bad["Atlant.Feed.C"] = true
	_ = f.SetLicenceKey(testKey, "admin")
	fs.set(200, sign(t, key_id, priv, manifest(t, *now,
		testPack("p1", 1, "Atlant.Feed.A"), testPack("p2", 1, "Atlant.Feed.B", "Atlant.Feed.C"))))
	if err := f.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sortedNames(inst), ","); got != "Atlant.Feed.A" {
		t.Errorf("installed %v (a pack must be all or nothing)", got)
	}
	for _, p := range f.Status().Packs {
		if (p.ID == "p2") != (p.InstallError != "") || (p.ID == "p2") == p.Installed {
			t.Errorf("%v: installed %v error %q", p.ID, p.Installed, p.InstallError)
		}
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	f, _, fs, key_id, priv, now := setup(t)
	_ = f.SetLicenceKey(testKey, "admin")
	fs.set(200, sign(t, key_id, priv, manifest(t, *now, testPack("p1", 1, "Atlant.Feed.A"))))
	if err := f.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.state_path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 && os.PathSeparator == '/' {
		t.Errorf("state file mode %v", info.Mode())
	}

	inst2 := newFakeInstaller()
	f2 := newFeeds(nil, inst2)
	f2.state_path = f.state_path
	f2.now = f.now
	f2.load()
	if s := f2.Status(); s.State != StateActive || len(inst2.names()) != 1 {
		t.Errorf("after restart: %v %v", s.State, inst2.names())
	}

	// Restarting after the lease ended does not bring the packs back.
	inst3 := newFakeInstaller()
	f3 := newFeeds(nil, inst3)
	f3.state_path = f.state_path
	later := now.Add(30 * 24 * time.Hour)
	f3.now = func() time.Time { return later }
	f3.load()
	if s := f3.Status(); s.State == StateActive || len(inst3.names()) != 0 {
		t.Errorf("after a late restart: %v %v", s.State, inst3.names())
	}
}

func TestNoKeysInBuild(t *testing.T) {
	old := feedPublicKeys
	feedPublicKeys = map[string]string{}
	defer func() { feedPublicKeys = old }()
	f := newFeeds(nil, newFakeInstaller())
	if s := f.Status(); s.State != StateNotConfigured {
		t.Errorf("state %v", s.State)
	}
	if err := f.SetLicenceKey(testKey, "admin"); !errors.Is(err, errNoKeys) {
		t.Errorf("got %v", err)
	}
}

func TestExamplePacks(t *testing.T) {
	packs, err := LoadPacks("../../docs/feeds/packs")
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) == 0 {
		t.Fatal("no example packs")
	}
	if err := CheckPackArtifacts(packs); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildManifest(packs, IssueOptions{LicenceKey: testKey,
		Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestFeedURLMustBeHTTPS(t *testing.T) {
	t.Setenv(FeedURLEnv, "http://feeds.example.com/v1/feed")
	if _, err := fetch(context.Background(), testKey, ""); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Errorf("got %v", err)
	}
}

func mustJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func sortedNames(inst *fakeInstaller) []string {
	names := inst.names()
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}
