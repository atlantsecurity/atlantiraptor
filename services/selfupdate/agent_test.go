package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceBinaryFromCommandLine(t *testing.T) {
	for in, want := range map[string]string{
		`"C:\Program Files\Atlant Security\Atlantiraptor\Atlantiraptor.exe" --config "C:\Program Files\Atlant Security\Atlantiraptor\client.config.yaml" service run`: `C:\Program Files\Atlant Security\Atlantiraptor\Atlantiraptor.exe`,
		`C:\Agent\Atlantiraptor.exe --config C:\Agent\client.config.yaml service run`:                                                                                 `C:\Agent\Atlantiraptor.exe`,
		`C:\Program Files\X\Atlantiraptor.EXE service run`:                                                                                                            `C:\Program Files\X\Atlantiraptor.EXE`,
		`"unterminated`: ``,
		``:              ``,
	} {
		if got := ServiceBinaryFromCommandLine(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.9", "1.0.10", -1, true},
		{"v1.1.0", "1.1.0", 0, true},
		{"2.0.0", "1.9.9", 1, true},
		{"0.77.4", "1.0.0", -1, true},
		{"dev", "1.0.0", 0, false},
	} {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("%v vs %v: got %v,%v", c.a, c.b, got, ok)
		}
	}
}

func TestDownloadReleaseAsset(t *testing.T) {
	body := []byte("the windows agent")
	sum := sha256.Sum256(body)
	listed := hex.EncodeToString(sum[:])
	const name = "Atlantiraptor-windows-amd64.exe"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tags/v1.2.3":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tag_name": "v1.2.3",
				"assets": []map[string]interface{}{
					{"name": name, "browser_download_url": srv.URL + "/dl/v1.2.3/" + name},
					{"name": SumsAssetName, "browser_download_url": srv.URL + "/dl/v1.2.3/" + SumsAssetName},
				},
			})
		case "/tags/v1.2.4":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tag_name": "v1.2.4", "prerelease": true})
		case "/dl/v1.2.3/" + SumsAssetName:
			fmt.Fprintf(w, "%s  %s\n", listed, name)
		case "/dl/v1.2.3/" + name:
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	releaseByTagURL = srv.URL + "/tags/"
	downloadPrefix = srv.URL + "/dl/"
	allowedHost = func(string) bool { return true }
	testInsecure = true
	t.Cleanup(func() {
		srv.Close()
		releaseByTagURL = "https://api.github.com/repos/" + Repository + "/releases/tags/"
		downloadPrefix = "https://github.com/" + Repository + "/releases/download/"
		allowedHost = isGitHubHost
		testInsecure = false
	})

	dir := t.TempDir()
	out := filepath.Join(dir, "agent.exe")
	got, err := DownloadReleaseAsset(context.Background(), "v1.2.3", name, out)
	if err != nil {
		t.Fatal(err)
	}
	if got != listed {
		t.Errorf("hash %v want %v", got, listed)
	}
	if data, _ := os.ReadFile(out); string(data) != string(body) {
		t.Error("content differs")
	}

	for _, v := range []string{"1.2.4", "1.2.5", "latest"} {
		if _, err := DownloadReleaseAsset(context.Background(), v, name,
			filepath.Join(dir, v)); err == nil {
			t.Errorf("%v: accepted", v)
		}
	}
	if _, err := DownloadReleaseAsset(context.Background(), "1.2.3", "other.exe",
		filepath.Join(dir, "other")); err == nil {
		t.Error("accepted a missing asset")
	}
}
