package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"v1.0.0", true}, {"1.2.3", true}, {"v10.20.30", true},
		{"", false}, {"v1.0", false}, {"v1.0.0-rc1", false}, {"v1.0.0.1", false},
		{"v01.0.0", false}, {"v-1.0.0", false}, {"latest", false},
	} {
		if _, ok := parseVersion(c.in); ok != c.ok {
			t.Errorf("%q: got %v want %v", c.in, ok, c.ok)
		}
	}
	a, _ := parseVersion("1.0.9")
	b, _ := parseVersion("1.0.10")
	c, _ := parseVersion("1.1.0")
	if !a.Less(b) || !b.Less(c) || c.Less(a) || a.Less(a) {
		t.Error("ordering is wrong")
	}
}

func TestParseSums(t *testing.T) {
	h := strings.Repeat("ab", 32)
	sums, err := parseSums(strings.NewReader(h + "  Atlantiraptor-windows-amd64.exe\n" +
		strings.ToUpper(h) + " *other.msi\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sums["Atlantiraptor-windows-amd64.exe"] != h || sums["other.msi"] != h {
		t.Errorf("got %v", sums)
	}
	for _, bad := range []string{"zz  file", h[:10] + "  file", h + " a b"} {
		if _, err := parseSums(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSignerNames(t *testing.T) {
	issuer := "C=US, O=Microsoft Corporation, CN=Microsoft ID Verified CS AOC CA 03"
	good := "C=BG, ST=Sofia City, L=Sofia, O=Atlant Security EOOD, CN=Atlant Security EOOD"
	if err := checkSignerNames(good, issuer); err != nil {
		t.Errorf("rejected the real signer: %v", err)
	}
	for _, c := range [][2]string{
		{"C=BG, O=Someone Else, CN=Atlant Security EOOD", issuer},
		{"C=BG, O=Atlant Security EOOD, CN=Atlant Security EOOD Ltd", issuer},
		{"C=BG, O=Atlant Security EOOD", issuer},
		{good, "C=US, O=Evil CA, CN=Microsoft ID Verified CS AOC CA 03"},
		{good, "C=US, O=Microsoft Corporation, CN=Some Other CA"},
	} {
		if err := checkSignerNames(c[0], c[1]); err == nil {
			t.Errorf("accepted %q / %q", c[0], c[1])
		}
	}
}

// The signed 1.0.0 release binary, when it is around (it is too big
// to keep in the repository).
func TestReadSignerFromRelease(t *testing.T) {
	path := os.Getenv("ATLANTIRAPTOR_SIGNED_EXE")
	if path == "" {
		t.Skip("set ATLANTIRAPTOR_SIGNED_EXE to a signed release binary")
	}
	subject, issuer, err := readSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSignerNames(subject, issuer); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedRejected(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBinary(exe); err == nil {
		t.Fatal("an unsigned binary passed verification")
	}
}

func TestRedirectsStayOnGitHub(t *testing.T) {
	for _, c := range []struct {
		u  string
		ok bool
	}{
		{"https://github.com/atlantsecurity/atlantiraptor/releases/download/v1.0.1/x", true},
		{"https://release-assets.githubusercontent.com/github-production-release-asset/1", true},
		{"https://objects.githubusercontent.com/x", true},
		{"http://github.com/x", false},
		{"https://github.com.evil.example/x", false},
		{"https://evilgithubusercontent.com/x", false},
		{"https://example.com/x", false},
	} {
		u, _ := url.Parse(c.u)
		if got := checkURL(u); got != c.ok {
			t.Errorf("%v: got %v want %v", c.u, got, c.ok)
		}
	}
}

func TestAssetURLMustBeThisRepo(t *testing.T) {
	a := &asset{Name: "Atlantiraptor-windows-amd64.exe",
		URL: "https://github.com/atlantsecurity/atlantiraptor/releases/download/v1.0.1/Atlantiraptor-windows-amd64.exe"}
	if _, err := assetURL("v1.0.1", a); err != nil {
		t.Error(err)
	}
	a.URL = "https://github.com/someone/fork/releases/download/v1.0.1/Atlantiraptor-windows-amd64.exe"
	if _, err := assetURL("v1.0.1", a); err == nil {
		t.Error("accepted another repository")
	}
}

// fakeGitHub serves a release with a binary and its checksum list.
func fakeGitHub(t *testing.T, tag string, body []byte, listed string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			name := currentAssetName()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tag_name": tag, "html_url": "https://example/rel",
				"assets": []map[string]interface{}{
					{"name": name, "browser_download_url": srv.URL + "/dl/" + tag + "/" + name},
					{"name": SumsAssetName, "browser_download_url": srv.URL + "/dl/" + tag + "/" + SumsAssetName},
				},
			})
		case "/dl/" + tag + "/" + SumsAssetName:
			fmt.Fprintf(w, "%s  %s\n", listed, currentAssetName())
		case "/dl/" + tag + "/" + currentAssetName():
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	latestReleaseURL = srv.URL + "/latest"
	downloadPrefix = srv.URL + "/dl/"
	allowedHost = func(string) bool { return true }
	testInsecure = true
	t.Cleanup(func() {
		srv.Close()
		latestReleaseURL = "https://api.github.com/repos/" + Repository + "/releases/latest"
		downloadPrefix = "https://github.com/" + Repository + "/releases/download/"
		allowedHost = isGitHubHost
		testInsecure = false
	})
	return srv
}

func TestCheckAndDownload(t *testing.T) {
	body := []byte("not really a binary")
	sum := sha256.Sum256(body)
	fakeGitHub(t, "v9.9.9", body, hex.EncodeToString(sum[:]))

	u := newUpdater(nil)
	s, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.LatestVersion != "9.9.9" || !s.LatestHasBinary || !s.UpdateAvailable {
		t.Fatalf("status %+v", s)
	}

	rel := u.latest
	a := rel.find(currentAssetName())
	addr, err := assetURL(rel.TagName, a)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "new.exe")
	if err := downloadVerified(context.Background(), addr, out, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != string(body) {
		t.Error("downloaded content differs")
	}

	// A wrong checksum leaves nothing behind.
	bad := strings.Repeat("00", 32)
	if err := downloadVerified(context.Background(), addr, out, bad); err == nil {
		t.Error("checksum mismatch accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("file left behind after a failed download")
	}
}

func TestSettingsPersist(t *testing.T) {
	dir := t.TempDir()
	u := newUpdater(nil)
	u.state_path = filepath.Join(dir, settingsFile)
	if !u.settings.AutoInstall || u.settings.CheckHours != DefaultCheckHours {
		t.Fatalf("defaults %+v", u.settings)
	}
	if _, err := u.SetSettings(false, 12, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.SetSettings(true, MaxCheckHours+1, "admin"); err == nil {
		t.Error("accepted too long an interval")
	}

	u2 := newUpdater(nil)
	u2.state_path = u.state_path
	u2.load()
	if u2.settings.AutoInstall || u2.settings.CheckHours != 12 || u2.settings.UpdatedBy != "admin" {
		t.Errorf("reloaded %+v", u2.settings)
	}

	// A pending record that did not take effect is reported once.
	if err := u2.save(&Pending{From: "", To: "9.9.9"}); err != nil {
		t.Fatal(err)
	}
	u3 := newUpdater(nil)
	u3.state_path = u.state_path
	u3.load()
	if !strings.Contains(u3.status.LastResult, "did not take effect") {
		t.Errorf("last result %q", u3.status.LastResult)
	}
	data, _ := os.ReadFile(u.state_path)
	if strings.Contains(string(data), "pending") {
		t.Error("pending record was not cleared")
	}
}

func TestInstallRefusedWhenNotRunning(t *testing.T) {
	u := newUpdater(nil)
	if err := u.Install(context.Background(), "admin"); err == nil {
		t.Error("install ran without the updater loop")
	}
}
