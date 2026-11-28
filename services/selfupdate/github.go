package selfupdate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"www.velocidex.com/golang/velociraptor/config"
)

// The repository is fixed at build time. Nothing at run time (config,
// API, console) can point the updater somewhere else.
const Repository = "atlantsecurity/atlantiraptor"

// SumsAssetName is the checksum list published with every release, in
// sha256sum format.
const SumsAssetName = "SHA256SUMS"

const (
	maxBinarySize = 512 << 20
	maxSumsSize   = 1 << 20
	maxAPISize    = 4 << 20
)

// Package variables so tests can point them at a local server.
var (
	latestReleaseURL = "https://api.github.com/repos/" + Repository + "/releases/latest"
	downloadPrefix   = "https://github.com/" + Repository + "/releases/download/"
	allowedHost      = isGitHubHost
	httpTransport    http.RoundTripper
)

type release struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	HTMLURL     string  `json:"html_url"`
	PublishedAt string  `json:"published_at"`
	Draft       bool    `json:"draft"`
	Prerelease  bool    `json:"prerelease"`
	Assets      []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

func (self *release) find(name string) *asset {
	for i := range self.Assets {
		if self.Assets[i].Name == name {
			return &self.Assets[i]
		}
	}
	return nil
}

// AssetName is the release asset holding the server binary for a
// platform, for example Atlantiraptor-windows-amd64.exe.
func AssetName(goos, goarch string) string {
	name := "Atlantiraptor-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func currentAssetName() string {
	return AssetName(runtime.GOOS, runtime.GOARCH)
}

func isGitHubHost(host string) bool {
	host = strings.ToLower(host)
	return host == "github.com" || host == "api.github.com" ||
		strings.HasSuffix(host, ".githubusercontent.com")
}

func httpClient(timeout time.Duration) *http.Client {
	transport := httpTransport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = http.ProxyFromEnvironment
		transport = t
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Downloads redirect from github.com to GitHub's asset hosts.
		// Never follow a redirect anywhere else, or to plain http.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !checkURL(req.URL) {
				return fmt.Errorf("refusing redirect to %v", req.URL.Host)
			}
			return nil
		},
	}
}

func checkURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && testInsecure) {
		return false
	}
	return allowedHost(u.Hostname())
}

// testInsecure lets tests use an httptest server.
var testInsecure = false

func userAgent() string {
	v := config.ReleaseVersion()
	if v == "" {
		v = "dev"
	}
	return "Atlantiraptor-updater/" + v
}

func fetchLatestRelease(ctx context.Context) (*release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent())

	resp, err := httpClient(30 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoRelease
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %v", resp.Status)
	}

	result := &release{}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxAPISize)).Decode(result)
	if err != nil {
		return nil, fmt.Errorf("reading the release from GitHub: %w", err)
	}
	if result.Draft || result.Prerelease {
		return nil, errNoRelease
	}
	return result, nil
}

var errNoRelease = errors.New("no release has been published on GitHub yet")

// assetURL checks that an asset is served from this repository's
// release downloads.
func assetURL(tag string, a *asset) (string, error) {
	want := downloadPrefix + url.PathEscape(tag) + "/" + url.PathEscape(a.Name)
	if a.URL != want {
		return "", fmt.Errorf("unexpected download address for %v", a.Name)
	}
	return want, nil
}

func download(ctx context.Context, address string, out io.Writer, limit int64) (int64, error) {
	u, err := url.Parse(address)
	if err != nil || !checkURL(u) {
		return 0, fmt.Errorf("refusing to download from %v", address)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := httpClient(20 * time.Minute).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download answered %v", resp.Status)
	}
	if resp.ContentLength > limit {
		return 0, fmt.Errorf("download is too large (%v bytes)", resp.ContentLength)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, errors.New("download is too large")
	}
	return n, nil
}

// parseSums reads sha256sum output ("<hex>  <name>" or "<hex> *<name>").
func parseSums(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("bad line in %v: %q", SumsAssetName, line)
		}
		sum := strings.ToLower(fields[0])
		raw, err := hex.DecodeString(sum)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("bad checksum in %v: %q", SumsAssetName, line)
		}
		result[strings.TrimPrefix(fields[1], "*")] = sum
	}
	return result, scanner.Err()
}

// downloadVerified downloads an asset to path and checks its SHA-256.
// The file is removed on any failure.
func downloadVerified(ctx context.Context, address, path, want string) (err error) {
	_ = os.Remove(path)
	fd, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	defer func() {
		cerr := fd.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()

	hash := sha256.New()
	_, err = download(ctx, address, io.MultiWriter(fd, hash), maxBinarySize)
	if err != nil {
		return err
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch: %v listed, %v downloaded", want, got)
	}
	return fd.Sync()
}

// releaseByTagURL is the GitHub API address of one release by its tag.
var releaseByTagURL = "https://api.github.com/repos/" + Repository + "/releases/tags/"

func fetchReleaseByTag(ctx context.Context, tag string) (*release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		releaseByTagURL+url.PathEscape(tag), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent())

	resp, err := httpClient(30 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release %v is not published on GitHub", tag)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %v", resp.Status)
	}
	result := &release{}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxAPISize)).Decode(result)
	if err != nil {
		return nil, fmt.Errorf("reading release %v from GitHub: %w", tag, err)
	}
	if result.Draft || result.Prerelease {
		return nil, fmt.Errorf("release %v is a draft or pre-release", tag)
	}
	return result, nil
}

// DownloadReleaseAsset downloads one asset of release vVERSION of this
// repository to path, checked against the release's SHA256SUMS. It
// returns the SHA-256 of the file. The file is removed on failure.
// The caller still has to check the signature (VerifyBinary).
func DownloadReleaseAsset(ctx context.Context, version, asset_name, path string) (string, error) {
	v, ok := parseVersion(version)
	if !ok {
		return "", fmt.Errorf("%q is not a release version", version)
	}
	tag := "v" + v.String()
	rel, err := fetchReleaseByTag(ctx, tag)
	if err != nil {
		return "", err
	}
	bin_asset := rel.find(asset_name)
	sums_asset := rel.find(SumsAssetName)
	if bin_asset == nil || sums_asset == nil {
		return "", fmt.Errorf("release %v has no %v with %v", tag, asset_name, SumsAssetName)
	}
	bin_url, err := assetURL(rel.TagName, bin_asset)
	if err != nil {
		return "", err
	}
	sums_url, err := assetURL(rel.TagName, sums_asset)
	if err != nil {
		return "", err
	}

	var sums_buf strings.Builder
	if _, err := download(ctx, sums_url, &sums_buf, maxSumsSize); err != nil {
		return "", fmt.Errorf("downloading %v: %w", SumsAssetName, err)
	}
	sums, err := parseSums(strings.NewReader(sums_buf.String()))
	if err != nil {
		return "", err
	}
	want, ok := sums[bin_asset.Name]
	if !ok {
		return "", fmt.Errorf("%v does not list %v", SumsAssetName, bin_asset.Name)
	}
	if err := downloadVerified(ctx, bin_url, path, want); err != nil {
		return "", fmt.Errorf("downloading %v: %w", bin_asset.Name, err)
	}
	return want, nil
}

// ParseVersion reports whether s is a plain MAJOR.MINOR.PATCH release
// number and returns it normalized (without a "v").
func ParseVersion(s string) (string, bool) {
	v, ok := parseVersion(s)
	if !ok {
		return "", false
	}
	return v.String(), true
}

// CompareVersions compares two release numbers: -1, 0 or 1. ok is
// false if either is not a release number.
func CompareVersions(a, b string) (result int, ok bool) {
	va, ok_a := parseVersion(a)
	vb, ok_b := parseVersion(b)
	if !ok_a || !ok_b {
		return 0, false
	}
	switch {
	case va.Less(vb):
		return -1, true
	case vb.Less(va):
		return 1, true
	}
	return 0, true
}
