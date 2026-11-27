// Package huntfeeds delivers Atlant Security's premium hunt feeds to an
// Atlantiraptor server.
//
// A server administrator enters the licence key bought from Atlant
// Security. The server then fetches the feed from Atlant's feed service
// every few hours: a manifest of hunt packs (VQL artifacts, indicator
// lists as artifact parameters, and how to hunt with them) signed with
// Atlant's feed signing key. Packs are loaded into the artifact
// repository as read-only Atlant.Feed.* artifacts and listed on the
// console's Hunt feeds page, where analysts start them as hunts.
//
// The feed service decides whether a licence key is good. Each manifest
// carries a lease (valid_until) of a couple of weeks at most, so a
// server that cannot reach the service keeps working for a while, and a
// server whose subscription ended loses the packs at the next check or
// when the lease runs out, whichever comes first.
package huntfeeds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
)

// States reported to the console.
const (
	StateNotConfigured = "not_configured" // this build has no feed signing key
	StateUnlicensed    = "unlicensed"     // no licence key entered
	StatePending       = "pending"        // key entered, no feed received yet
	StateActive        = "active"         // packs are available
	StateExpired       = "expired"        // the subscription ended
	StateInvalid       = "invalid"        // the service does not know the key
)

const (
	stateFileName = "atlantiraptor_hunt_feeds.json"
	syncInterval  = 6 * time.Hour
	retryInterval = time.Hour
	firstSync     = 30 * time.Second
	// A pack shows as new or updated for this long.
	freshFor = 14 * 24 * time.Hour
)

// Seen records when this server first saw a pack and its version.
type Seen struct {
	FirstVersion int   `json:"first_version"`
	FirstSeen    int64 `json:"first_seen"`
	Version      int   `json:"version"`
	VersionSeen  int64 `json:"version_seen"`
}

type stateFile struct {
	LicenceKey string           `json:"licence_key,omitempty"`
	KeySetBy   string           `json:"key_set_by,omitempty"`
	KeySetAt   int64            `json:"key_set_at,omitempty"`
	Bundle     string           `json:"bundle,omitempty"`
	LastIssued time.Time        `json:"last_issued,omitempty"`
	Rejected   string           `json:"rejected,omitempty"`
	Message    string           `json:"message,omitempty"`
	LastSync   int64            `json:"last_sync,omitempty"`
	Seen       map[string]*Seen `json:"seen,omitempty"`
}

// LicenceInfo is the subscription as the feed service describes it.
type LicenceInfo struct {
	ID       string `json:"id,omitempty"`
	Customer string `json:"customer,omitempty"`
	Plan     string `json:"plan,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
}

// PackStatus is a pack as the console shows it.
type PackStatus struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	Published    int64    `json:"published,omitempty"`
	Updated      int64    `json:"updated,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Category     string   `json:"category,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Platforms    []string `json:"platforms,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Description  string   `json:"description,omitempty"`
	References   []string `json:"references,omitempty"`
	Changes      string   `json:"changes,omitempty"`
	Artifacts    []string `json:"artifacts"`
	Hunt         HuntSpec `json:"hunt"`
	Fresh        string   `json:"fresh,omitempty"` // "new", "updated" or ""
	FirstSeen    int64    `json:"first_seen,omitempty"`
	VersionSeen  int64    `json:"version_seen,omitempty"`
	Installed    bool     `json:"installed"`
	InstallError string   `json:"install_error,omitempty"`
}

// Status is a snapshot for the console. It never contains the key.
type Status struct {
	Running      bool         `json:"running"`
	State        string       `json:"state"`
	HasKey       bool         `json:"has_key"`
	MaskedKey    string       `json:"masked_key,omitempty"`
	KeySetBy     string       `json:"key_set_by,omitempty"`
	KeySetAt     int64        `json:"key_set_at,omitempty"`
	Licence      *LicenceInfo `json:"licence,omitempty"`
	Feed         string       `json:"feed,omitempty"`
	Issued       int64        `json:"issued,omitempty"`
	UsableUntil  int64        `json:"usable_until,omitempty"`
	LastSync     int64        `json:"last_sync,omitempty"`
	NextSync     int64        `json:"next_sync,omitempty"`
	Syncing      bool         `json:"syncing"`
	Message      string       `json:"message,omitempty"`
	LastError    string       `json:"last_error,omitempty"`
	FeedURL      string       `json:"feed_url"`
	SubscribeURL string       `json:"subscribe_url"`
	Packs        []PackStatus `json:"packs"`
	NewCount     int          `json:"new_count"`
	UpdatedCount int          `json:"updated_count"`
}

// Installer puts pack artifacts into the artifact repository.
type Installer interface {
	// Install loads one artifact definition and returns its name.
	Install(definition string) (string, error)
	Remove(name string)
}

type Feeds struct {
	mu         sync.Mutex
	config_obj *config_proto.Config
	state_path string
	installer  Installer
	now        func() time.Time

	st        stateFile
	manifest  *Manifest
	installed map[string]string // artifact name -> pack id
	failed    map[string]string // pack id -> install error
	syncing   bool
	running   bool
	next_sync time.Time
	last_err  string
	wake      chan struct{}
}

var (
	global_mu sync.Mutex
	global    *Feeds
)

// Get returns the server's feeds. It exists (and reports status) even
// when the background loop was never started.
func Get() *Feeds {
	global_mu.Lock()
	defer global_mu.Unlock()
	if global == nil {
		global = newFeeds(nil, nil)
	}
	return global
}

func newFeeds(config_obj *config_proto.Config, installer Installer) *Feeds {
	self := &Feeds{
		config_obj: config_obj,
		installer:  installer,
		now:        time.Now,
		installed:  map[string]string{},
		failed:     map[string]string{},
		wake:       make(chan struct{}, 1),
	}
	if config_obj != nil && config_obj.Datastore != nil &&
		config_obj.Datastore.Location != "" {
		self.state_path = filepath.Join(config_obj.Datastore.Location, stateFileName)
	}
	self.st.Seen = map[string]*Seen{}
	return self
}

// Start loads the saved feed and keeps it current in the background.
// It only runs on the master frontend.
func Start(ctx context.Context, wg *sync.WaitGroup, config_obj *config_proto.Config) {
	if !services.IsMaster(config_obj) {
		return
	}
	self := newFeeds(config_obj, &repositoryInstaller{config_obj: config_obj})
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

func (self *Feeds) logger() *logging.LogContext {
	config_obj := self.config_obj
	if config_obj == nil {
		config_obj = config.GetDefaultConfig()
	}
	return logging.GetLogger(config_obj, &logging.FrontendComponent)
}

// load reads the saved state and re-installs the saved feed if it is
// still good.
func (self *Feeds) load() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.state_path == "" {
		return
	}
	data, err := os.ReadFile(self.state_path)
	if err != nil {
		return
	}
	st := stateFile{}
	if err := json.Unmarshal(data, &st); err != nil {
		self.logger().Error("hunt feeds: unreadable %v: %v", self.state_path, err)
		return
	}
	if st.Seen == nil {
		st.Seen = map[string]*Seen{}
	}
	self.st = st
	if st.Bundle == "" || st.LicenceKey == "" {
		return
	}
	m, err := ParseBundle([]byte(st.Bundle), publicKeys())
	if err == nil {
		err = m.CheckFor(st.LicenceKey, self.now())
	}
	if err != nil {
		self.logger().Info("hunt feeds: the saved feed is no longer usable: %v", err)
		self.dropLocked(err)
		return
	}
	self.applyLocked(m)
	self.logger().Info("hunt feeds: loaded %d packs (usable until %v)", len(m.Packs),
		m.UsableUntil().UTC().Format(time.RFC3339))
}

// saveLocked writes the state atomically; the file holds the licence key.
func (self *Feeds) saveLocked() error {
	if self.state_path == "" {
		return nil
	}
	data, err := json.MarshalIndent(self.st, "", " ")
	if err != nil {
		return err
	}
	tmp := self.state_path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, self.state_path)
}

func (self *Feeds) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

func (self *Feeds) loop(ctx context.Context) {
	self.mu.Lock()
	self.next_sync = self.now().Add(firstSync)
	self.mu.Unlock()

	for {
		self.mu.Lock()
		wait := time.Until(self.next_sync)
		if self.manifest != nil {
			if until := time.Until(self.manifest.UsableUntil()); until < wait {
				wait = until
			}
		}
		self.mu.Unlock()
		if wait < time.Second {
			wait = time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-self.wake:
			self.mu.Lock()
			self.next_sync = self.now()
			self.mu.Unlock()
		}

		self.enforceLease()

		self.mu.Lock()
		due := !self.now().Before(self.next_sync)
		self.mu.Unlock()
		if due {
			sync_ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			_ = self.Sync(sync_ctx)
			cancel()
		}
	}
}

// enforceLease removes the packs once the saved feed may no longer be used.
func (self *Feeds) enforceLease() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.manifest == nil {
		return
	}
	if err := self.manifest.CheckFor(self.st.LicenceKey, self.now()); err != nil {
		self.logger().Info("hunt feeds: %v; removing the feed packs", err)
		self.dropLocked(err)
		_ = self.saveLocked()
	}
}

// Sync asks the feed service for the current feed now.
func (self *Feeds) Sync(ctx context.Context) error {
	self.mu.Lock()
	if self.syncing {
		self.mu.Unlock()
		return errors.New("a sync is already running")
	}
	key := self.st.LicenceKey
	if key == "" || len(publicKeys()) == 0 {
		self.next_sync = self.now().Add(syncInterval)
		self.mu.Unlock()
		return nil
	}
	self.syncing = true
	server_id := serverID(self.config_obj)
	self.mu.Unlock()

	body, err := fetch(ctx, key, server_id)

	self.mu.Lock()
	defer self.mu.Unlock()
	self.syncing = false
	now := self.now()
	self.st.LastSync = now.Unix()

	// The key may have changed while we were away.
	if self.st.LicenceKey != key {
		self.next_sync = now
		return nil
	}

	var rej *rejection
	switch {
	case errors.As(err, &rej):
		if self.st.Rejected != rej.state || self.manifest != nil {
			self.logger().Info("hunt feeds: %v", rej.message)
			self.auditLocked("hunt_feed_rejected", ordereddict.NewDict().
				Set("state", rej.state).Set("message", rej.message))
		}
		self.removeAllLocked()
		self.manifest = nil
		self.st.Bundle = ""
		self.st.Rejected = rej.state
		self.st.Message = rej.message
		self.last_err = ""
		self.next_sync = now.Add(syncInterval)
		_ = self.saveLocked()
		return rej

	case err != nil:
		self.last_err = err.Error()
		self.next_sync = now.Add(retryInterval)
		self.logger().Error("hunt feeds: %v", err)
		_ = self.saveLocked()
		return err
	}

	m, err := ParseBundle(body, publicKeys())
	if err == nil {
		err = m.CheckFor(key, now)
	}
	if err == nil && m.Issued.Before(self.st.LastIssued) {
		err = fmt.Errorf("the feed service sent a feed older than the one already installed (%v)",
			m.Issued.UTC().Format(time.RFC3339))
	}
	if errors.Is(err, errExpired) {
		self.removeAllLocked()
		self.manifest = nil
		self.st.Bundle = ""
		self.st.Rejected = StateExpired
		self.st.Message = "The subscription has ended."
		self.last_err = ""
		self.next_sync = now.Add(syncInterval)
		_ = self.saveLocked()
		return err
	}
	if err != nil {
		self.last_err = "The feed was not accepted: " + err.Error()
		self.next_sync = now.Add(retryInterval)
		self.logger().Error("hunt feeds: %v", self.last_err)
		_ = self.saveLocked()
		return err
	}

	was_active := self.manifest != nil
	self.applyLocked(m)
	self.st.Bundle = string(body)
	self.st.LastIssued = m.Issued
	self.st.Rejected = ""
	self.st.Message = ""
	self.last_err = ""
	self.next_sync = now.Add(syncInterval)
	_ = self.saveLocked()
	if !was_active {
		self.auditLocked("hunt_feed_activated", ordereddict.NewDict().
			Set("licence", m.Licence.ID).Set("customer", m.Licence.Customer).
			Set("plan", m.Licence.Plan).Set("packs", len(m.Packs)))
	}
	self.logger().Info("hunt feeds: <green>%d packs</> from %v (usable until %v)",
		len(m.Packs), m.Feed, m.UsableUntil().UTC().Format(time.RFC3339))
	return nil
}

// applyLocked installs the manifest's packs and removes artifacts of
// packs that are no longer in the feed.
func (self *Feeds) applyLocked(m *Manifest) {
	now := self.now().Unix()
	wanted := map[string]string{}
	for _, p := range m.Packs {
		for _, name := range p.ArtifactNames() {
			wanted[name] = p.ID
		}
	}
	for name := range self.installed {
		if _, ok := wanted[name]; !ok {
			self.removeLocked(name)
		}
	}

	self.failed = map[string]string{}
	for _, p := range m.Packs {
		for _, def := range p.Artifacts {
			if self.installer == nil {
				break
			}
			name, err := self.installer.Install(def)
			if err != nil {
				self.failed[p.ID] = err.Error()
				self.logger().Error("hunt feeds: pack %v: %v", p.ID, err)
				continue
			}
			self.installed[name] = p.ID
		}
		if self.failed[p.ID] != "" {
			// A pack is all or nothing: don't leave half of it behind.
			for _, name := range p.ArtifactNames() {
				self.removeLocked(name)
			}
		}

		seen, ok := self.st.Seen[p.ID]
		if !ok {
			seen = &Seen{FirstVersion: p.Version, FirstSeen: now, Version: p.Version, VersionSeen: now}
			self.st.Seen[p.ID] = seen
		} else if seen.Version != p.Version {
			seen.Version = p.Version
			seen.VersionSeen = now
		}
	}
	self.manifest = m
}

func (self *Feeds) removeLocked(name string) {
	if self.installer != nil {
		self.installer.Remove(name)
	}
	delete(self.installed, name)
}

func (self *Feeds) removeAllLocked() {
	for name := range self.installed {
		self.removeLocked(name)
	}
	self.failed = map[string]string{}
}

// dropLocked removes the packs because the saved feed is unusable.
func (self *Feeds) dropLocked(reason error) {
	self.removeAllLocked()
	self.manifest = nil
	self.st.Bundle = ""
	switch {
	case errors.Is(reason, errExpired):
		self.st.Rejected = StateExpired
		self.st.Message = "The subscription has ended."
	case errors.Is(reason, errLeaseOver):
		self.st.Rejected = ""
		self.st.Message = "The feed service could not be reached to renew the feed, so its packs were removed. They come back at the next successful sync."
	default:
		self.st.Message = reason.Error()
	}
}

// SetLicenceKey saves a new key (or removes it when empty) and syncs.
func (self *Feeds) SetLicenceKey(key, principal string) error {
	key = strings.TrimSpace(key)
	if len(key) > 512 || strings.ContainsAny(key, " \t\r\n") {
		return errors.New("that does not look like a licence key")
	}
	if key != "" && len(publicKeys()) == 0 {
		return errNoKeys
	}
	self.mu.Lock()
	old := self.st.LicenceKey
	self.removeAllLocked()
	self.manifest = nil
	self.st.Bundle = ""
	self.st.LastIssued = time.Time{}
	self.st.Rejected = ""
	self.st.Message = ""
	self.last_err = ""
	self.st.LicenceKey = key
	self.st.KeySetBy = principal
	self.st.KeySetAt = self.now().Unix()
	if key == "" {
		self.st.KeySetBy, self.st.KeySetAt = "", 0
	}
	err := self.saveLocked()
	op := "hunt_feed_licence_set"
	if key == "" {
		op = "hunt_feed_licence_removed"
	}
	self.auditAs(principal, op, ordereddict.NewDict().Set("key", maskKey(key)).
		Set("previous", maskKey(old)))
	self.mu.Unlock()
	self.poke()
	return err
}

// Status returns a snapshot for the console.
func (self *Feeds) Status() Status {
	self.mu.Lock()
	defer self.mu.Unlock()
	now := self.now()
	s := Status{
		Running:      self.running,
		HasKey:       self.st.LicenceKey != "",
		MaskedKey:    maskKey(self.st.LicenceKey),
		KeySetBy:     self.st.KeySetBy,
		KeySetAt:     self.st.KeySetAt,
		LastSync:     self.st.LastSync,
		Syncing:      self.syncing,
		Message:      self.st.Message,
		LastError:    self.last_err,
		FeedURL:      feedURL(),
		SubscribeURL: SubscribeURL,
		Packs:        []PackStatus{},
	}
	if self.running && s.HasKey && !self.next_sync.IsZero() {
		s.NextSync = self.next_sync.Unix()
	}

	switch {
	case len(publicKeys()) == 0:
		s.State = StateNotConfigured
	case !s.HasKey:
		s.State = StateUnlicensed
	case self.manifest != nil:
		s.State = StateActive
	case self.st.Rejected != "":
		s.State = self.st.Rejected
	default:
		s.State = StatePending
	}

	m := self.manifest
	if m == nil {
		return s
	}
	s.Licence = &LicenceInfo{ID: m.Licence.ID, Customer: m.Licence.Customer,
		Plan: m.Licence.Plan, Expires: m.Licence.Expires.Unix()}
	s.Feed = m.Feed
	s.Issued = m.Issued.Unix()
	s.UsableUntil = m.UsableUntil().Unix()

	for _, p := range m.Packs {
		ps := PackStatus{
			ID: p.ID, Name: p.Name, Version: p.Version,
			Published: unix(p.Published), Updated: unix(p.Updated),
			Severity: p.Severity, Category: p.Category, Tags: p.Tags, Platforms: p.Platforms,
			Summary: p.Summary, Description: p.Description, References: p.References,
			Changes: p.Changes, Artifacts: p.ArtifactNames(), Hunt: p.Hunt,
			InstallError: self.failed[p.ID],
		}
		ps.Installed = ps.InstallError == "" && self.installer != nil
		if seen := self.st.Seen[p.ID]; seen != nil {
			ps.FirstSeen, ps.VersionSeen = seen.FirstSeen, seen.VersionSeen
			switch {
			case now.Sub(time.Unix(seen.FirstSeen, 0)) < freshFor:
				ps.Fresh = "new"
				s.NewCount++
			case seen.Version != seen.FirstVersion && now.Sub(time.Unix(seen.VersionSeen, 0)) < freshFor:
				ps.Fresh = "updated"
				s.UpdatedCount++
			}
		}
		s.Packs = append(s.Packs, ps)
	}
	sort.SliceStable(s.Packs, func(i, j int) bool {
		a, b := s.Packs[i], s.Packs[j]
		if a.Updated != b.Updated {
			return a.Updated > b.Updated
		}
		return a.Name < b.Name
	})
	return s
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (self *Feeds) auditLocked(op string, details *ordereddict.Dict) {
	self.auditAs("hunt-feeds", op, details)
}

func (self *Feeds) auditAs(principal, op string, details *ordereddict.Dict) {
	if self.config_obj == nil {
		return
	}
	config_obj := self.config_obj
	go func() {
		_ = services.LogAudit(context.Background(), config_obj, principal, op, details)
	}()
}

// maskKey shows enough of a key to recognise it.
func maskKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return strings.Repeat("•", len(key))
	}
	return key[:4] + "…" + key[len(key)-4:]
}

// serverID identifies this installation to the feed service without
// revealing anything about it: a hash of the deployment's CA
// certificate, which is unique to each installation.
func serverID(config_obj *config_proto.Config) string {
	if config_obj == nil || config_obj.Client == nil || config_obj.Client.CaCertificate == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(config_obj.Client.CaCertificate))
	return hex.EncodeToString(sum[:16])
}
