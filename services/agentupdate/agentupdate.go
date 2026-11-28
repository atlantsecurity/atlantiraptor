// Package agentupdate upgrades Windows agents to the server's release.
//
// Servers update themselves from Atlant Security's signed GitHub
// releases (services/selfupdate). This service then brings the agents
// along: it takes the Windows binary of the same release (or of a
// pinned version), checks it against the release's SHA256SUMS and
// Atlant Security's Authenticode signature, hosts it in every org as
// the AtlantiraptorAgentWindows tool, and schedules
// Admin.Client.Upgrade.Atlantiraptor on agents that run an older
// version:
//
//  1. a canary group first (CanaryPercent of the Windows agents, at
//     least one), chosen anew for each release;
//  2. after CanaryHours, if at most 20% of the canary upgrades failed
//     and at least one succeeded, every other Windows agent. Otherwise
//     the rollout pauses until an administrator resumes it.
//
// Only agents seen in the last 15 minutes are sent the upgrade, at
// most 200 per round (every 5 minutes). Each agent gets up to three
// attempts, six hours apart. Agents with the opt-out label are left
// alone. On the agent the artifact checks the hash and signature again
// and the new binary rolls itself back if it does not stay running.
//
// Linux and macOS agents are not upgraded: releases carry no signed
// binaries for them yet.
package agentupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
)

const (
	ArtifactName = "Admin.Client.Upgrade.Atlantiraptor"
	ToolName     = "AtlantiraptorAgentWindows"
	// The release asset that holds the Windows agent (the agent and
	// server are one binary).
	WindowsAsset = "Atlantiraptor-windows-amd64.exe"

	// DisableEnv turns automatic agent upgrades off regardless of the
	// saved setting.
	DisableEnv = "ATLANTIRAPTOR_DISABLE_AGENT_UPDATE"

	DefaultCanaryPercent = 10
	DefaultCanaryHours   = 24
	MaxCanaryHours       = 24 * 14
	DefaultExcludeLabel  = "no-auto-upgrade"

	stateFileName = "atlantiraptor_agent_update.json"
	cacheDirName  = "agent_update"

	tickInterval   = 5 * time.Minute
	firstTickDelay = 3 * time.Minute
)

type Settings struct {
	Enabled       bool   `json:"enabled"`
	PinnedVersion string `json:"pinned_version,omitempty"`
	CanaryPercent int    `json:"canary_percent"`
	CanaryHours   int    `json:"canary_hours"`
	ExcludeLabel  string `json:"exclude_label"`
	UpdatedBy     string `json:"updated_by,omitempty"`
	Updated       int64  `json:"updated,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{
		Enabled:       true,
		CanaryPercent: DefaultCanaryPercent,
		CanaryHours:   DefaultCanaryHours,
		ExcludeLabel:  DefaultExcludeLabel,
	}
}

// Validate checks and normalizes settings from the console.
func (self Settings) Validate() (Settings, error) {
	if self.PinnedVersion = strings.TrimSpace(self.PinnedVersion); self.PinnedVersion != "" {
		v, ok := selfupdate.ParseVersion(self.PinnedVersion)
		if !ok {
			return self, fmt.Errorf("pinned version %q is not a release number like 1.2.3", self.PinnedVersion)
		}
		self.PinnedVersion = v
	}
	if self.CanaryPercent < 0 || self.CanaryPercent > 100 {
		return self, errors.New("canary percent must be between 0 and 100")
	}
	if self.CanaryHours < 0 || self.CanaryHours > MaxCanaryHours {
		return self, fmt.Errorf("canary hours must be between 0 and %d", MaxCanaryHours)
	}
	self.ExcludeLabel = strings.TrimSpace(self.ExcludeLabel)
	if len(self.ExcludeLabel) > 128 {
		return self, errors.New("the opt-out label is too long")
	}
	return self, nil
}

// BinaryInfo describes the agent binary being rolled out.
type BinaryInfo struct {
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Signer   string `json:"signer"`
	Source   string `json:"source"`
	Prepared int64  `json:"prepared"`
	path     string
}

type stateFile struct {
	Settings Settings    `json:"settings"`
	Rollout  *Rollout    `json:"rollout,omitempty"`
	Binary   *BinaryInfo `json:"binary,omitempty"`
}

type Status struct {
	Running       bool           `json:"running"`
	State         string         `json:"state"`
	Reason        string         `json:"reason,omitempty"`
	ServerVersion string         `json:"server_version"`
	Target        string         `json:"target,omitempty"`
	Settings      Settings       `json:"settings"`
	DisabledByEnv bool           `json:"disabled_by_env,omitempty"`
	Phase         string         `json:"phase,omitempty"`
	PhaseChanged  int64          `json:"phase_changed,omitempty"`
	Started       int64          `json:"started,omitempty"`
	CanaryUntil   int64          `json:"canary_until,omitempty"`
	PausedReason  string         `json:"paused_reason,omitempty"`
	Binary        *BinaryInfo    `json:"binary,omitempty"`
	Counts        Counts         `json:"counts"`
	Failed        []FailedClient `json:"failed"`
	LastTick      int64          `json:"last_tick,omitempty"`
	NextTick      int64          `json:"next_tick,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	LastScheduled int            `json:"last_scheduled"`
	SupportedOS   []string       `json:"supported_os"`
	ArtifactName  string         `json:"artifact_name"`
	ToolName      string         `json:"tool_name"`
}

// backend is the I/O the service needs; tests replace it.
type backend interface {
	// The binary for version, checked and cached.
	PrepareBinary(ctx context.Context, version string, cached *BinaryInfo) (*BinaryInfo, error)
	// Host the binary as the tool in every org.
	PublishTool(ctx context.Context, bin *BinaryInfo) error
	ListClients(ctx context.Context, exclude_label string) ([]clientView, error)
	FlowResult(ctx context.Context, org_id, client_id, flow_id string) flowResult
	Schedule(ctx context.Context, org_id, client_id, target string) (string, error)
	Audit(ctx context.Context, principal, operation string, details map[string]interface{})
}

type Service struct {
	mu         sync.Mutex
	config_obj *config_proto.Config
	state_path string
	cache_dir  string
	settings   Settings
	rollout    *Rollout
	binary     *BinaryInfo
	status     Status
	backend    backend
	running    bool
	ticking    bool
	wake       chan struct{}
	now        func() time.Time
}

var (
	global_mu sync.Mutex
	global    *Service
)

// Get returns the server's agent update service. It exists (and can
// report status) even when the background loop was never started.
func Get() *Service {
	global_mu.Lock()
	defer global_mu.Unlock()
	if global == nil {
		global = newService(nil, nil)
	}
	return global
}

func newService(config_obj *config_proto.Config, b backend) *Service {
	self := &Service{
		config_obj: config_obj,
		settings:   DefaultSettings(),
		backend:    b,
		wake:       make(chan struct{}, 1),
		now:        time.Now,
	}
	if config_obj != nil && config_obj.Datastore != nil &&
		config_obj.Datastore.Location != "" {
		self.state_path = filepath.Join(config_obj.Datastore.Location, stateFileName)
		self.cache_dir = filepath.Join(config_obj.Datastore.Location, cacheDirName)
	}
	self.status.State = "idle"
	return self
}

// Start runs the service in the background on the master server.
func Start(ctx context.Context, wg *sync.WaitGroup, config_obj *config_proto.Config) {
	if !services.IsMaster(config_obj) {
		return
	}
	self := newService(config_obj, nil)
	self.backend = &serverBackend{config_obj: config_obj, cache_dir: self.cache_dir}
	self.running = true
	self.load()

	global_mu.Lock()
	global = self
	global_mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		self.loop(ctx)
	}()
}

func (self *Service) logger() *logging.LogContext {
	config_obj := self.config_obj
	if config_obj == nil {
		config_obj = config.GetDefaultConfig()
	}
	return logging.GetLogger(config_obj, &logging.FrontendComponent)
}

func (self *Service) load() {
	if self.state_path == "" {
		return
	}
	data, err := os.ReadFile(self.state_path)
	if err != nil {
		return
	}
	state := stateFile{Settings: DefaultSettings()}
	if err := json.Unmarshal(data, &state); err != nil {
		self.logger().Error("agent update: unreadable %v: %v", self.state_path, err)
		return
	}
	if s, err := state.Settings.Validate(); err == nil {
		self.settings = s
	}
	self.rollout = state.Rollout
	if self.rollout != nil && self.rollout.Clients == nil {
		self.rollout.Clients = make(map[string]*ClientState)
	}
	self.binary = state.Binary
	if self.binary != nil {
		self.binary.path = binaryCachePath(self.cache_dir, self.binary.Version)
	}
}

// saveLocked writes the state atomically. Call with mu held.
func (self *Service) saveLocked() error {
	if self.state_path == "" {
		return nil
	}
	data, err := json.MarshalIndent(stateFile{
		Settings: self.settings, Rollout: self.rollout, Binary: self.binary}, "", " ")
	if err != nil {
		return err
	}
	tmp := self.state_path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, self.state_path)
}

func disabledByEnv() bool {
	v := strings.ToLower(os.Getenv(DisableEnv))
	return v != "" && v != "0" && v != "false"
}

// target is the version agents should run: the pinned one, else the
// server's own release. "" means none (a development server).
func (self *Service) targetLocked() string {
	if self.settings.PinnedVersion != "" {
		return self.settings.PinnedVersion
	}
	v, _ := selfupdate.ParseVersion(config.ReleaseVersion())
	return v
}

// Status returns a snapshot for the console.
func (self *Service) Status() Status {
	self.mu.Lock()
	defer self.mu.Unlock()
	s := self.status
	s.Running = self.running
	s.ServerVersion = config.ReleaseVersion()
	s.Target = self.targetLocked()
	s.Settings = self.settings
	s.DisabledByEnv = disabledByEnv()
	s.SupportedOS = []string{"windows"}
	s.ArtifactName = ArtifactName
	s.ToolName = ToolName
	if s.Failed == nil {
		s.Failed = []FailedClient{}
	}
	if b := self.binary; b != nil {
		copy := *b
		s.Binary = &copy
	}
	if r := self.rollout; r != nil && r.Target == s.Target {
		s.Phase = r.Phase
		s.PhaseChanged = r.PhaseChanged
		s.Started = r.Started
		s.PausedReason = r.PausedReason
		if r.Phase == PhaseCanary {
			s.CanaryUntil = time.Unix(r.Started, 0).Add(
				time.Duration(self.settings.CanaryHours) * time.Hour).Unix()
		}
	}
	return s
}

// SetSettings saves new settings; principal is recorded and audited.
func (self *Service) SetSettings(ctx context.Context, s Settings, principal string) (Status, error) {
	s, err := s.Validate()
	if err != nil {
		return self.Status(), err
	}
	s.UpdatedBy = principal
	s.Updated = self.now().Unix()

	self.mu.Lock()
	old := self.settings
	self.settings = s
	err = self.saveLocked()
	self.mu.Unlock()

	if self.backend != nil {
		self.backend.Audit(ctx, principal, "agent_update_settings", map[string]interface{}{
			"enabled": s.Enabled, "pinned_version": s.PinnedVersion,
			"canary_percent": s.CanaryPercent, "canary_hours": s.CanaryHours,
			"exclude_label": s.ExcludeLabel,
			"was_enabled":   old.Enabled, "was_pinned_version": old.PinnedVersion,
		})
	}
	self.poke()
	return self.Status(), err
}

// Resume moves a paused (or canary) rollout to every agent.
func (self *Service) Resume(ctx context.Context, principal string) (Status, error) {
	self.mu.Lock()
	r := self.rollout
	if r == nil || r.Target != self.targetLocked() {
		self.mu.Unlock()
		return self.Status(), errors.New("there is no rollout to resume")
	}
	r.setPhase(PhaseAll, self.now())
	err := self.saveLocked()
	target := r.Target
	self.mu.Unlock()
	if self.backend != nil {
		self.backend.Audit(ctx, principal, "agent_update_resume",
			map[string]interface{}{"target": target})
	}
	self.poke()
	return self.Status(), err
}

// RetryFailed gives agents whose upgrade failed new attempts.
func (self *Service) RetryFailed(ctx context.Context, principal string) (Status, error) {
	self.mu.Lock()
	n := 0
	if r := self.rollout; r != nil {
		for _, st := range r.Clients {
			if st.State == StateFailed || st.State == StateRetry {
				st.State = ""
				st.Attempts = 0
				st.Error = ""
				st.NextAttempt = 0
				n++
			}
		}
	}
	err := self.saveLocked()
	self.mu.Unlock()
	if self.backend != nil {
		self.backend.Audit(ctx, principal, "agent_update_retry_failed",
			map[string]interface{}{"clients": n})
	}
	self.poke()
	return self.Status(), err
}

// RunNow starts a round right away.
func (self *Service) RunNow() {
	self.poke()
}

func (self *Service) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

func (self *Service) loop(ctx context.Context) {
	delay := firstTickDelay
	for {
		self.mu.Lock()
		self.status.NextTick = self.now().Add(delay).Unix()
		self.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		case <-self.wake:
		}
		self.Tick(ctx)
		delay = tickInterval
	}
}

func (self *Service) setIdle(state, reason string) {
	self.mu.Lock()
	self.status.State = state
	self.status.Reason = reason
	self.status.LastTick = self.now().Unix()
	self.mu.Unlock()
}

func (self *Service) setError(err error) {
	self.mu.Lock()
	self.status.LastError = err.Error()
	self.status.State = "error"
	self.status.LastTick = self.now().Unix()
	self.mu.Unlock()
}

// Tick runs one round of the rollout.
func (self *Service) Tick(ctx context.Context) {
	self.mu.Lock()
	if self.ticking || self.backend == nil {
		self.mu.Unlock()
		return
	}
	self.ticking = true
	settings := self.settings
	target := self.targetLocked()
	cached := self.binary
	self.mu.Unlock()
	defer func() {
		self.mu.Lock()
		self.ticking = false
		self.mu.Unlock()
	}()

	switch {
	case !settings.Enabled:
		self.setIdle("disabled", "Automatic agent upgrades are turned off.")
		return
	case disabledByEnv():
		self.setIdle("disabled", "Turned off on this server by "+DisableEnv+".")
		return
	case target == "":
		self.setIdle("idle",
			"This server is a development build with no release version; pin a version to upgrade agents.")
		return
	}

	// 1. The binary for the target, checked, and hosted in every org.
	bin, err := self.backend.PrepareBinary(ctx, target, cached)
	if err != nil {
		self.setError(fmt.Errorf("getting the %v agent: %w", target, err))
		self.logger().Error("agent update: %v", err)
		return
	}
	self.mu.Lock()
	changed := self.binary == nil || self.binary.SHA256 != bin.SHA256
	self.binary = bin
	if changed {
		_ = self.saveLocked()
	}
	self.mu.Unlock()

	if err := self.backend.PublishTool(ctx, bin); err != nil {
		self.setError(fmt.Errorf("hosting the %v agent: %w", target, err))
		self.logger().Error("agent update: %v", err)
		return
	}

	// 2. The fleet.
	clients, err := self.backend.ListClients(ctx, settings.ExcludeLabel)
	if err != nil {
		self.setError(fmt.Errorf("listing clients: %w", err))
		return
	}

	now := self.now()
	self.mu.Lock()
	if self.rollout == nil || self.rollout.Target != target {
		from := ""
		if self.rollout != nil {
			from = self.rollout.Target
		}
		self.rollout = newRollout(target, now, settings.CanaryPercent)
		self.mu.Unlock()
		self.backend.Audit(ctx, "AgentUpdateService", "agent_update_rollout_started",
			map[string]interface{}{"target": target, "previous": from,
				"canary_percent": settings.CanaryPercent, "canary_hours": settings.CanaryHours})
		self.logger().Info("agent update: <green>rolling out %v</> to Windows agents", target)
		self.mu.Lock()
	}
	r := self.rollout
	self.mu.Unlock()

	// The console's actions change the rollout too, so it is only
	// touched under the lock.
	self.mu.Lock()
	res := r.tick(tickInput{
		Now:      now,
		Settings: settings,
		Clients:  clients,
		Flow: func(st *ClientState) flowResult {
			return self.backend.FlowResult(ctx, st.OrgId, st.ClientId, st.FlowId)
		},
	})
	self.mu.Unlock()

	for _, e := range res.Events {
		self.logger().Info("agent update: %v", e)
	}

	// 3. Send the upgrade.
	views := make(map[string]clientView, len(clients))
	for _, c := range clients {
		views[c.key()] = c
	}
	scheduled := 0
	var last_err error
	for _, st := range res.Schedule {
		flow_id, err := self.backend.Schedule(ctx, st.OrgId, st.ClientId, target)
		self.mu.Lock()
		if err != nil {
			r.scheduleFailed(st, now, err)
			last_err = err
		} else {
			st.scheduled(flow_id, views[st.OrgId+"/"+st.ClientId].label(), now)
			scheduled++
		}
		self.mu.Unlock()
	}
	if scheduled > 0 {
		self.logger().Info("agent update: sent the %v upgrade to %d agents (%v phase)",
			target, scheduled, r.Phase)
		res.Counts.Upgrading += scheduled
		res.Counts.Waiting -= scheduled
	}

	self.mu.Lock()
	self.status.Counts = res.Counts
	self.status.Failed = res.Failed
	self.status.LastTick = now.Unix()
	self.status.LastScheduled = scheduled
	self.status.Reason = ""
	self.status.State = "rolling out"
	if r.Phase == PhasePaused {
		self.status.State = "paused"
	} else if res.Counts.Windows > 0 && res.Counts.UpToDate+res.Counts.Excluded+
		res.Counts.Failed == res.Counts.Windows {
		self.status.State = "done"
	}
	self.status.LastError = ""
	if last_err != nil {
		self.status.LastError = "Scheduling upgrades: " + last_err.Error()
	}
	_ = self.saveLocked()
	self.mu.Unlock()
}
