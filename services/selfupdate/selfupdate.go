// Package selfupdate keeps an Atlantiraptor server on the latest
// release published on GitHub.
//
// The server checks atlantsecurity/atlantiraptor's latest GitHub
// release every few hours. When a newer release has a binary for this
// platform, it downloads it next to the running binary, checks it
// against the release's SHA256SUMS, requires a trusted Authenticode
// signature from Atlant Security's certificate, runs it once to
// confirm it starts and reports the expected version, then swaps it in
// and restarts hidden in the background. The previous binary is kept
// as <name>.old until the next start.
//
// What cannot change the source: the repository is a build-time
// constant and redirects only go to GitHub's own hosts. What cannot
// change the outcome: the checksum list could be replaced by whoever
// controls the release, but the Authenticode signature can only come
// from Atlant Security's Artifact Signing account. Only server
// administrators can trigger an install or change the settings.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
)

// WaitPIDEnv tells a freshly installed binary which process to wait
// for before it starts (the one it replaced).
const WaitPIDEnv = "ATLANTIRAPTOR_SELF_UPDATE_WAIT_PID"

// DisableEnv turns off automatic installs regardless of the saved
// setting (checks and manual installs still work).
const DisableEnv = "ATLANTIRAPTOR_DISABLE_AUTO_UPDATE"

const (
	DefaultCheckHours = 6
	MaxCheckHours     = 24 * 7
	settingsFile      = "atlantiraptor_self_update.json"
	firstCheckDelay   = 2 * time.Minute
)

type Settings struct {
	AutoInstall bool   `json:"auto_install"`
	CheckHours  int    `json:"check_hours"`
	UpdatedBy   string `json:"updated_by,omitempty"`
	Updated     int64  `json:"updated,omitempty"`
}

func defaultSettings() Settings {
	return Settings{AutoInstall: true, CheckHours: DefaultCheckHours}
}

// Pending is written just before a restart into a new version, so the
// new process can report how the update went.
type Pending struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   int64  `json:"at"`
	By   string `json:"by"`
}

type stateFile struct {
	Settings Settings `json:"settings"`
	Pending  *Pending `json:"pending,omitempty"`
}

type Status struct {
	Running          bool     `json:"running"`
	CurrentVersion   string   `json:"current_version"`
	DevBuild         bool     `json:"dev_build"`
	Platform         string   `json:"platform"`
	InstallSupported bool     `json:"install_supported"`
	Repository       string   `json:"repository"`
	Settings         Settings `json:"settings"`
	AutoDisabledEnv  bool     `json:"auto_disabled_by_env,omitempty"`
	LatestVersion    string   `json:"latest_version,omitempty"`
	LatestURL        string   `json:"latest_url,omitempty"`
	LatestPublished  string   `json:"latest_published,omitempty"`
	LatestHasBinary  bool     `json:"latest_has_binary"`
	UpdateAvailable  bool     `json:"update_available"`
	LastCheck        int64    `json:"last_check,omitempty"`
	NextCheck        int64    `json:"next_check,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
	State            string   `json:"state"`
	LastResult       string   `json:"last_result,omitempty"`
}

type Updater struct {
	mu         sync.Mutex
	config_obj *config_proto.Config
	state_path string
	settings   Settings
	status     Status
	latest     *release
	installing bool
	wake       chan struct{}
	shutdown   func()
	running    bool
}

var (
	global_mu sync.Mutex
	global    *Updater
)

// Get returns the server's updater. It exists (and can report status)
// even when the background loop was never started.
func Get() *Updater {
	global_mu.Lock()
	defer global_mu.Unlock()
	if global == nil {
		global = newUpdater(nil)
	}
	return global
}

func newUpdater(config_obj *config_proto.Config) *Updater {
	self := &Updater{
		config_obj: config_obj,
		settings:   defaultSettings(),
		wake:       make(chan struct{}, 1),
	}
	if config_obj != nil && config_obj.Datastore != nil &&
		config_obj.Datastore.Location != "" {
		self.state_path = filepath.Join(config_obj.Datastore.Location, settingsFile)
	}
	self.status.State = "idle"
	return self
}

func currentVersion() string {
	return config.ReleaseVersion()
}

// Start begins checking for updates in the background. shutdown stops
// the server in an orderly way; it is called after a new binary was
// installed and launched.
func Start(ctx context.Context, wg *sync.WaitGroup,
	config_obj *config_proto.Config, shutdown func()) {
	if !services.IsMaster(config_obj) {
		return
	}

	self := newUpdater(config_obj)
	self.shutdown = shutdown
	self.running = true
	self.load()
	cleanupOld()

	global_mu.Lock()
	global = self
	global_mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		self.loop(ctx)
	}()
}

func (self *Updater) logger() *logging.LogContext {
	config_obj := self.config_obj
	if config_obj == nil {
		config_obj = config.GetDefaultConfig()
	}
	return logging.GetLogger(config_obj, &logging.FrontendComponent)
}

func (self *Updater) load() {
	if self.state_path == "" {
		return
	}
	data, err := os.ReadFile(self.state_path)
	if err != nil {
		return
	}
	state := stateFile{Settings: defaultSettings()}
	if err := json.Unmarshal(data, &state); err != nil {
		self.logger().Error("self update: unreadable %v: %v", self.state_path, err)
		return
	}
	self.settings = normalize(state.Settings)

	if p := state.Pending; p != nil {
		if p.To == currentVersion() {
			self.status.LastResult = fmt.Sprintf("Updated from %v to %v at %v.",
				orDev(p.From), p.To, time.Unix(p.At, 0).UTC().Format(time.RFC3339))
			self.logger().Info("self update: <green>now running %v</> (was %v)", p.To, orDev(p.From))
		} else {
			self.status.LastResult = fmt.Sprintf("The update to %v did not take effect: still running %v.",
				p.To, orDev(currentVersion()))
			self.logger().Error("self update: update to %v did not take effect", p.To)
		}
		_ = self.save(nil)
	}
}

func orDev(v string) string {
	if v == "" {
		return "a development build"
	}
	return v
}

func normalize(s Settings) Settings {
	if s.CheckHours <= 0 {
		s.CheckHours = DefaultCheckHours
	}
	if s.CheckHours > MaxCheckHours {
		s.CheckHours = MaxCheckHours
	}
	return s
}

// save writes the settings (and an optional pending record) atomically.
func (self *Updater) save(pending *Pending) error {
	if self.state_path == "" {
		return nil
	}
	data, err := json.MarshalIndent(stateFile{Settings: self.settings, Pending: pending}, "", " ")
	if err != nil {
		return err
	}
	tmp := self.state_path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, self.state_path)
}

func autoDisabledByEnv() bool {
	v := strings.ToLower(os.Getenv(DisableEnv))
	return v != "" && v != "0" && v != "false"
}

// Status returns a snapshot for the console.
func (self *Updater) Status() Status {
	self.mu.Lock()
	defer self.mu.Unlock()
	s := self.status
	s.Running = self.running
	s.CurrentVersion = currentVersion()
	s.DevBuild = s.CurrentVersion == ""
	s.Platform = runtime.GOOS + "/" + runtime.GOARCH
	s.InstallSupported = installSupported
	s.Repository = Repository
	s.Settings = self.settings
	s.AutoDisabledEnv = autoDisabledByEnv()
	s.UpdateAvailable = self.updateAvailableLocked()
	return s
}

func (self *Updater) updateAvailableLocked() bool {
	if self.latest == nil {
		return false
	}
	latest, ok := parseVersion(self.latest.TagName)
	if !ok {
		return false
	}
	current, ok := parseVersion(currentVersion())
	if !ok {
		// A development build: any release is "newer".
		return true
	}
	return current.Less(latest)
}

// SetSettings changes the settings; principal is recorded.
func (self *Updater) SetSettings(auto_install bool, check_hours int, principal string) (Settings, error) {
	if check_hours < 0 || check_hours > MaxCheckHours {
		return Settings{}, fmt.Errorf("check_hours must be between 1 and %d", MaxCheckHours)
	}
	self.mu.Lock()
	self.settings = normalize(Settings{
		AutoInstall: auto_install,
		CheckHours:  check_hours,
		UpdatedBy:   principal,
		Updated:     time.Now().Unix(),
	})
	err := self.save(nil)
	s := self.settings
	self.mu.Unlock()
	self.poke()
	return s, err
}

func (self *Updater) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

func (self *Updater) loop(ctx context.Context) {
	delay := firstCheckDelay
	for {
		self.mu.Lock()
		self.status.NextCheck = time.Now().Add(delay).Unix()
		self.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		case <-self.wake:
			// Settings changed: recompute the schedule from the last check.
			self.mu.Lock()
			last := self.status.LastCheck
			hours := self.settings.CheckHours
			self.mu.Unlock()
			if last != 0 {
				next := time.Unix(last, 0).Add(time.Duration(hours) * time.Hour)
				delay = time.Until(next)
				if delay < time.Second {
					delay = time.Second
				}
				continue
			}
		}

		_, err := self.Check(ctx)
		if err == nil {
			self.maybeAutoInstall(ctx)
		}

		self.mu.Lock()
		delay = time.Duration(self.settings.CheckHours) * time.Hour
		self.mu.Unlock()
	}
}

func (self *Updater) maybeAutoInstall(ctx context.Context) {
	s := self.Status()
	if !s.UpdateAvailable || !s.LatestHasBinary || !s.InstallSupported ||
		!s.Settings.AutoInstall || s.AutoDisabledEnv || s.DevBuild {
		return
	}
	self.logger().Info("self update: installing %v automatically", s.LatestVersion)
	if err := self.Install(ctx, "self-update (automatic)"); err != nil {
		self.logger().Error("self update: %v", err)
	}
}

// Check asks GitHub for the latest release.
func (self *Updater) Check(ctx context.Context) (Status, error) {
	self.mu.Lock()
	if self.installing {
		self.mu.Unlock()
		return self.Status(), errors.New("an update is being installed")
	}
	self.status.State = "checking"
	self.mu.Unlock()

	rel, err := fetchLatestRelease(ctx)

	self.mu.Lock()
	self.status.State = "idle"
	self.status.LastCheck = time.Now().Unix()
	if err != nil {
		self.status.LastError = "Checking GitHub: " + err.Error()
		if errors.Is(err, errNoRelease) {
			self.latest = nil
			self.status.LatestVersion = ""
		}
		self.mu.Unlock()
		return self.Status(), err
	}
	if _, ok := parseVersion(rel.TagName); !ok {
		self.status.LastError = fmt.Sprintf("The latest release tag %q is not a version number.", rel.TagName)
		self.mu.Unlock()
		return self.Status(), errors.New(self.status.LastError)
	}
	self.status.LastError = ""
	self.setLatestLocked(rel)
	self.mu.Unlock()
	return self.Status(), nil
}

func (self *Updater) setLatestLocked(rel *release) {
	self.latest = rel
	self.status.LatestVersion = strings.TrimPrefix(rel.TagName, "v")
	self.status.LatestURL = rel.HTMLURL
	self.status.LatestPublished = rel.PublishedAt
	self.status.LatestHasBinary = rel.find(currentAssetName()) != nil &&
		rel.find(SumsAssetName) != nil
}

func (self *Updater) setState(state string) {
	self.mu.Lock()
	self.status.State = state
	self.mu.Unlock()
}

func (self *Updater) fail(err error) error {
	self.mu.Lock()
	self.status.State = "idle"
	self.status.LastError = "Installing: " + err.Error()
	self.installing = false
	self.mu.Unlock()
	return err
}

// Install downloads, verifies and switches to the latest release, then
// restarts the server. On success the process exits shortly after.
func (self *Updater) Install(ctx context.Context, principal string) error {
	if !installSupported {
		return errUnsupported
	}
	self.mu.Lock()
	if self.installing {
		self.mu.Unlock()
		return errors.New("an update is already being installed")
	}
	if !self.running {
		self.mu.Unlock()
		return errors.New("self update is not running in this process")
	}
	self.installing = true
	self.mu.Unlock()

	self.setState("checking")
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return self.fail(err)
	}
	self.mu.Lock()
	self.status.LastCheck = time.Now().Unix()
	self.setLatestLocked(rel)
	available := self.updateAvailableLocked()
	self.mu.Unlock()

	target, ok := parseVersion(rel.TagName)
	if !ok {
		return self.fail(fmt.Errorf("release tag %q is not a version", rel.TagName))
	}
	if !available {
		return self.fail(fmt.Errorf("already running %v, the latest release", currentVersion()))
	}

	bin_asset := rel.find(currentAssetName())
	sums_asset := rel.find(SumsAssetName)
	if bin_asset == nil || sums_asset == nil {
		return self.fail(fmt.Errorf("release %v has no %v with %v", rel.TagName,
			currentAssetName(), SumsAssetName))
	}
	bin_url, err := assetURL(rel.TagName, bin_asset)
	if err != nil {
		return self.fail(err)
	}
	sums_url, err := assetURL(rel.TagName, sums_asset)
	if err != nil {
		return self.fail(err)
	}

	exe, err := executablePath()
	if err != nil {
		return self.fail(err)
	}
	new_path := exe + ".new"
	old_path := exe + ".old"

	// 1. The checksum list.
	self.setState("downloading")
	var sums_buf strings.Builder
	if _, err := download(ctx, sums_url, &sums_buf, maxSumsSize); err != nil {
		return self.fail(fmt.Errorf("downloading %v: %w", SumsAssetName, err))
	}
	sums, err := parseSums(strings.NewReader(sums_buf.String()))
	if err != nil {
		return self.fail(err)
	}
	want, ok := sums[bin_asset.Name]
	if !ok {
		return self.fail(fmt.Errorf("%v does not list %v", SumsAssetName, bin_asset.Name))
	}

	// 2. The binary, checked against the list as it arrives.
	if err := downloadVerified(ctx, bin_url, new_path, want); err != nil {
		return self.fail(fmt.Errorf("downloading %v: %w", bin_asset.Name, err))
	}

	// 3. Atlant Security's signature, trusted by Windows.
	self.setState("verifying")
	subject, err := VerifyBinary(new_path)
	if err != nil {
		_ = os.Remove(new_path)
		return self.fail(err)
	}

	// 4. It runs, and is the version it claims to be.
	if err := smokeTest(ctx, new_path, target.String()); err != nil {
		_ = os.Remove(new_path)
		return self.fail(err)
	}

	// 5. Swap and restart.
	self.setState("restarting")
	_ = os.Remove(old_path)
	if err := os.Rename(exe, old_path); err != nil {
		_ = os.Remove(new_path)
		return self.fail(fmt.Errorf("moving the current binary aside: %w", err))
	}
	if err := os.Rename(new_path, exe); err != nil {
		_ = os.Rename(old_path, exe)
		_ = os.Remove(new_path)
		return self.fail(fmt.Errorf("putting the new binary in place: %w", err))
	}

	pending := &Pending{From: currentVersion(), To: target.String(),
		At: time.Now().Unix(), By: principal}
	self.mu.Lock()
	_ = self.save(pending)
	self.mu.Unlock()

	service_name := ""
	if self.config_obj != nil && self.config_obj.Client != nil &&
		self.config_obj.Client.WindowsInstaller != nil {
		service_name = self.config_obj.Client.WindowsInstaller.ServiceName
	}
	if err := relaunch(exe, os.Args[1:], service_name); err != nil {
		// Put the old binary back; this process keeps running.
		_ = os.Rename(exe, new_path)
		_ = os.Rename(old_path, exe)
		_ = os.Remove(new_path)
		self.mu.Lock()
		_ = self.save(nil)
		self.mu.Unlock()
		return self.fail(fmt.Errorf("starting the new version: %w", err))
	}

	self.audit(ctx, principal, pending, subject)
	self.logger().Info("self update: <green>installed %v</> (signed by %v); restarting", target, subject)

	go self.exit()
	return nil
}

func (self *Updater) audit(ctx context.Context, principal string, p *Pending, subject string) {
	if self.config_obj == nil {
		return
	}
	_ = services.LogAudit(ctx, self.config_obj, principal, "server_self_update",
		ordereddict.NewDict().Set("from", orDev(p.From)).Set("to", p.To).
			Set("signer", subject).Set("repository", Repository))
}

// exit stops the server so the new binary can take over the ports.
func (self *Updater) exit() {
	time.Sleep(time.Second)
	if self.shutdown != nil {
		self.shutdown()
	}
	// Give an orderly shutdown time, then make sure we are gone: the
	// new process is waiting for this one to exit.
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// smokeTest runs the new binary's "selfupdate version" command.
func smokeTest(ctx context.Context, path, want string) error {
	sub_ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(sub_ctx, path, "selfupdate", "version")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the new binary did not run: %w", err)
	}
	got := strings.TrimSpace(string(out))
	if got != want {
		return fmt.Errorf("the new binary reports version %q, the release is %v", got, want)
	}
	return nil
}

// cleanupOld removes the binary left behind by the last update.
func cleanupOld() {
	exe, err := executablePath()
	if err == nil {
		_ = os.Remove(exe + ".old")
		_ = os.Remove(exe + ".new")
	}
}

// WaitForPreviousProcess is called first thing in main(). After an
// update, the new process waits here until the one it replaced has
// exited and released the ports.
func WaitForPreviousProcess() {
	v := os.Getenv(WaitPIDEnv)
	if v == "" {
		return
	}
	_ = os.Unsetenv(WaitPIDEnv)
	pid, err := strconv.Atoi(v)
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return
	}
	waitForPID(pid, 2*time.Minute)
}
