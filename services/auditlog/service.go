package auditlog

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	vjson "www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services/secrets"
	"www.velocidex.com/golang/velociraptor/utils/syslog"
)

// EnvDirectory, when set on the server, fixes the log directory; the
// console can then not change it.
const EnvDirectory = "ATLANTIRAPTOR_AUDIT_DIR"

const (
	maxDetails     = 64 << 10
	maxPending     = 5000
	tickEvery      = 10 * time.Second
	verifyEvery    = 6 * time.Hour
	principalSelf  = "AuditLog"
	syslogProtoUDP = "udp"
)

// Settings are kept in the datastore and edited in the console.
type Settings struct {
	// Empty: the default directory.
	Directory string         `json:"directory"`
	Syslog    SyslogSettings `json:"syslog"`
	UpdatedBy string         `json:"updated_by,omitempty"`
	Updated   int64          `json:"updated,omitempty"`
}

// SyslogSettings forward every entry, as written, to a syslog server
// or SIEM.
type SyslogSettings struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`   // host:port
	Protocol string `json:"protocol"` // udp, tcp or tls
}

// Status is shown on the console page.
type Status struct {
	Enabled          bool     `json:"enabled"`
	Reason           string   `json:"reason,omitempty"`
	Directory        string   `json:"directory"`
	DirectorySource  string   `json:"directory_source"` // env, settings, default
	DefaultDirectory string   `json:"default_directory"`
	EnvOverride      bool     `json:"env_override"`
	KeyId            string   `json:"key_id,omitempty"`
	PublicKey        string   `json:"public_key,omitempty"`
	Head             Head     `json:"head"`
	Files            int      `json:"files"`
	Bytes            int64    `json:"bytes"`
	LastVerify       *Result  `json:"last_verify,omitempty"`
	Verifying        bool     `json:"verifying"`
	WriteErrors      int      `json:"write_errors"`
	LastWriteError   string   `json:"last_write_error,omitempty"`
	Settings         Settings `json:"settings"`
	Forward          struct {
		Active    bool   `json:"active"`
		Sent      int64  `json:"sent"`
		Dropped   int64  `json:"dropped"`
		LastError string `json:"last_error,omitempty"`
	} `json:"forward"`
}

type pendingEvent struct {
	when      time.Time
	org_id    string
	principal string
	operation string
	details   json.RawMessage
}

// Service owns the server's audit log. There is one per process.
type Service struct {
	mu sync.Mutex

	ctx        context.Context
	config_obj *config_proto.Config
	started    bool
	reason     string

	key      ed25519.PrivateKey
	log      *Log
	settings Settings
	source   string

	anchors     map[string]Head
	anchorDirty bool

	lastVerify *Result
	verifying  bool

	writeErrors    int
	lastWriteError string

	forwarder   io.Writer
	fwdSent     int64
	fwdDropped  int64
	fwdLastErr  string
	hostname    string
	pending     []pendingEvent
	pendingLost int
}

var global = &Service{}

// Get returns the process's audit log service.
func Get() *Service { return global }

// Record adds an audit event. Before Start (or when the log could not
// be opened) events are kept in memory and written once it opens.
func Record(org_id, principal, operation string, details interface{}) error {
	return global.Record(org_id, principal, operation, details)
}

func encodeDetails(details interface{}) json.RawMessage {
	if details == nil {
		return json.RawMessage("{}")
	}
	data, err := vjson.Marshal(details)
	if err != nil || !json.Valid(data) {
		data, _ = json.Marshal(map[string]string{"unencodable": fmt.Sprintf("%v", details)})
	}
	if len(data) > maxDetails {
		sum := sha256.Sum256(data)
		data, _ = json.Marshal(map[string]interface{}{
			"truncated": true,
			"bytes":     len(data),
			"sha256":    hex.EncodeToString(sum[:]),
			"preview":   string(data[:4096]),
		})
	}
	return data
}

func (s *Service) Record(org_id, principal, operation string, details interface{}) error {
	raw := encodeDetails(details)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		if len(s.pending) < maxPending {
			s.pending = append(s.pending, pendingEvent{
				when: time.Now(), org_id: org_id, principal: principal,
				operation: operation, details: raw})
		} else {
			s.pendingLost++
		}
		if s.started {
			return fmt.Errorf("audit log is not open: %v", s.reason)
		}
		return nil
	}
	return s.appendLocked(org_id, principal, operation, raw)
}

func (s *Service) appendLocked(org_id, principal, operation string, details interface{}) error {
	_, err := s.log.Append(org_id, principal, operation, details)
	if err != nil {
		s.writeErrors++
		s.lastWriteError = err.Error()
		if s.config_obj != nil {
			logging.GetLogger(s.config_obj, &logging.FrontendComponent).
				Error("<red>Audit log</> could not write %v by %v: %v", operation, principal, err)
		}
	}
	return err
}

// DefaultDirectory is where the log goes unless configured: under
// ProgramData on Windows, next to the datastore elsewhere.
func DefaultDirectory(config_obj *config_proto.Config) string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Atlantiraptor", "AuditLog")
	}
	if config_obj != nil && config_obj.Datastore != nil && config_obj.Datastore.Location != "" {
		return filepath.Join(filepath.Dir(filepath.Clean(config_obj.Datastore.Location)), "atlantiraptor-audit")
	}
	return ""
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// isInside reports whether path is dir or below it.
func isInside(path, dir string) bool {
	if dir == "" {
		return false
	}
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	if samePath(path, dir) {
		return true
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// ValidateDirectory checks a directory chosen for the log: absolute,
// and outside the datastore and file store.
func ValidateDirectory(config_obj *config_proto.Config, dir string) error {
	if dir == "" {
		return nil
	}
	if strings.ContainsRune(dir, 0) || !filepath.IsAbs(dir) {
		return errors.New("Enter a full path, for example D:\\AuditLog.")
	}
	if config_obj != nil && config_obj.Datastore != nil {
		for _, store := range []string{config_obj.Datastore.Location, config_obj.Datastore.FilestoreDirectory} {
			if store != "" && (isInside(dir, store) || isInside(store, dir)) {
				return fmt.Errorf("The audit log must be kept outside the datastore (%v).", store)
			}
		}
	}
	return nil
}

func (s *Service) resolveDirLocked() (string, string) {
	if env := strings.TrimSpace(os.Getenv(EnvDirectory)); env != "" {
		return filepath.Clean(env), "env"
	}
	if s.settings.Directory != "" {
		return filepath.Clean(s.settings.Directory), "settings"
	}
	return DefaultDirectory(s.config_obj), "default"
}

// ---- datastore records ----

func settingsPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_audit_log").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func anchorPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_audit_anchor").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func readJSON(config_obj *config_proto.Config, p api.FSPathSpec, v interface{}) error {
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return errors.New("file store unavailable")
	}
	if _, err := fs.StatFile(p); err != nil {
		return err
	}
	reader, err := fs.ReadFile(p)
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(config_obj *config_proto.Config, p api.FSPathSpec, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return errors.New("file store unavailable")
	}
	writer, err := fs.WriteFile(p)
	if err != nil {
		return err
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}

type anchorDoc struct {
	// Newest position per directory.
	Heads map[string]Head `json:"heads"`
}

func (s *Service) anchorKey(dir string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(filepath.Clean(dir))
	}
	return filepath.Clean(dir)
}

func (s *Service) flushAnchorLocked() {
	if !s.anchorDirty || s.log == nil || s.config_obj == nil {
		return
	}
	s.anchors[s.anchorKey(s.log.Dir())] = s.log.Head()
	if err := writeJSON(s.config_obj, anchorPath(), &anchorDoc{Heads: s.anchors}); err == nil {
		s.anchorDirty = false
	}
}

// ---- start and stop ----

// Start opens the log for the server (master node only) and keeps it
// checkpointed until ctx is done.
func Start(ctx context.Context, wg *sync.WaitGroup, config_obj *config_proto.Config) {
	if config_obj.Frontend != nil && config_obj.Frontend.IsMinion {
		return
	}
	global.start(ctx, wg, config_obj)
}

func (s *Service) start(ctx context.Context, wg *sync.WaitGroup, config_obj *config_proto.Config) {
	logger := logging.GetLogger(config_obj, &logging.FrontendComponent)

	s.mu.Lock()
	s.ctx = ctx
	s.config_obj = config_obj
	s.started = true
	s.anchors = map[string]Head{}
	s.hostname, _ = os.Hostname()

	var settings Settings
	if err := readJSON(config_obj, settingsPath(), &settings); err == nil {
		s.settings = settings
	}
	var anchors anchorDoc
	if err := readJSON(config_obj, anchorPath(), &anchors); err == nil && anchors.Heads != nil {
		s.anchors = anchors.Heads
	}

	dek, err := secrets.GetDek(ctx, config_obj)
	if err != nil {
		s.reason = "The server has no secrets key to sign the audit log with: " + err.Error()
		s.mu.Unlock()
		logger.Error("<red>Audit log</> disabled: %v", s.reason)
		return
	}
	s.key = DeriveKey(dek)

	dir, source := s.resolveDirLocked()
	s.source = source
	if err := s.openLocked(dir, nil); err != nil {
		logger.Error("<red>Audit log</> could not open %v: %v", dir, err)
	} else {
		logger.Info("<green>Audit log</> is written to %v (key %v)", dir, s.log.KeyId())
	}
	s.configureForwarderLocked()
	s.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loop(ctx)
	}()

	go s.RunVerify()
}

// openLocked opens dir and writes the start event and anything queued.
func (s *Service) openLocked(dir string, extra map[string]interface{}) error {
	if dir == "" {
		s.reason = "No directory is configured for the audit log."
		return errors.New(s.reason)
	}
	if err := ValidateDirectory(s.config_obj, dir); err != nil {
		s.reason = err.Error()
		return err
	}
	genesis := map[string]interface{}{
		"directory": dir,
		"hostname":  s.hostname,
		"version":   versionString(),
	}
	for k, v := range extra {
		genesis[k] = v
	}
	l, err := Open(dir, s.key, Options{
		GenesisDetails: genesis,
		OnWrite:        s.onWrite,
	})
	if err != nil {
		s.reason = err.Error()
		return err
	}
	s.log = l
	s.reason = ""
	s.anchorDirty = true

	details := map[string]interface{}{
		"directory": dir,
		"hostname":  s.hostname,
		"version":   versionString(),
		"pid":       os.Getpid(),
		"key_id":    l.KeyId(),
	}
	for k, v := range extra {
		details[k] = v
	}
	if prev, ok := s.anchors[s.anchorKey(dir)]; ok {
		details["recorded_head"] = prev
	}
	_ = s.appendLocked("", principalSelf, "audit_log_opened", details)

	for _, p := range s.pending {
		var d interface{} = p.details
		var m map[string]interface{}
		if json.Unmarshal(p.details, &m) == nil {
			m["queued_at"] = p.when.UTC().Format(time.RFC3339Nano)
			d = m
		}
		_ = s.appendLocked(p.org_id, p.principal, p.operation, d)
	}
	if s.pendingLost > 0 {
		_ = s.appendLocked("", principalSelf, "audit_log_events_lost",
			map[string]interface{}{"count": s.pendingLost,
				"reason": "more events arrived than could be held while the log was not open"})
	}
	s.pending = nil
	s.pendingLost = 0
	s.flushAnchorLocked()
	return nil
}

func versionString() string {
	if v := config.ReleaseVersion(); v != "" {
		return v
	}
	return config.GetVersion().Version + " (development)"
}

func (s *Service) loop(ctx context.Context) {
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	nextVerify := time.Now().Add(verifyEvery)
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.log != nil {
				_ = s.log.Tick()
			}
			s.flushAnchorLocked()
			s.mu.Unlock()
			if time.Now().After(nextVerify) {
				nextVerify = time.Now().Add(verifyEvery)
				go s.RunVerify()
			}
		}
	}
}

func (s *Service) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return
	}
	_ = s.appendLocked("", principalSelf, "audit_log_closed",
		map[string]interface{}{"reason": "server stopping"})
	_ = s.log.Close("shutdown")
	s.anchorDirty = true
	s.anchors[s.anchorKey(s.log.Dir())] = s.log.Head()
	_ = writeJSON(s.config_obj, anchorPath(), &anchorDoc{Heads: s.anchors})
	s.log = nil
	s.started = false
	s.reason = "The server is stopping."
}

// onWrite runs under the Log's lock for every line written.
func (s *Service) onWrite(e *Entry, line []byte) {
	s.anchorDirty = true
	if e.Type == TypeCheckpoint {
		// Keep the datastore position close behind signed checkpoints.
		go func() {
			s.mu.Lock()
			s.flushAnchorLocked()
			s.mu.Unlock()
		}()
	}
	s.forward(e, line)
}

// ---- syslog forwarding ----

// SyslogMessage formats one entry as an RFC 5424 message: facility
// local0, severity notice, app name Atlantiraptor, msgid audit, the
// line as written as the message.
func SyslogMessage(hostname string, e *Entry, line []byte) string {
	if hostname == "" {
		hostname = "-"
	}
	return fmt.Sprintf("<133>1 %s %s Atlantiraptor %d audit - %s",
		e.Time, strings.ReplaceAll(hostname, " ", "_"), os.Getpid(), line)
}

func (s *Service) configureForwarderLocked() {
	s.forwarder = nil
	s.fwdLastErr = ""
	cfg := s.settings.Syslog
	if !cfg.Enabled || cfg.Server == "" || s.ctx == nil {
		return
	}
	if syslog.Factory == nil {
		s.fwdLastErr = "syslog support is not built in"
		return
	}
	protocol := cfg.Protocol
	if protocol == "" {
		protocol = syslogProtoUDP
	}
	var client *config_proto.ClientConfig
	if s.config_obj != nil {
		client = s.config_obj.Client
	}
	w, err := syslog.Factory(s.ctx, client, protocol, cfg.Server, "", 30*time.Second)
	if err != nil {
		s.fwdLastErr = err.Error()
		return
	}
	s.forwarder = w
}

func (s *Service) forward(e *Entry, line []byte) {
	if s.forwarder == nil {
		return
	}
	if _, err := s.forwarder.Write([]byte(SyslogMessage(s.hostname, e, line))); err != nil {
		s.fwdDropped++
		s.fwdLastErr = err.Error()
		return
	}
	s.fwdSent++
}

// ---- console operations ----

func dirStats(dir string) (int, int64) {
	files, err := ListFiles(dir)
	if err != nil {
		return 0, 0
	}
	var size int64
	for _, f := range files {
		if st, err := os.Stat(filepath.Join(dir, f)); err == nil {
			size += st.Size()
		}
	}
	return len(files), size
}

// Status describes the log for the console.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled:          s.log != nil,
		Reason:           s.reason,
		DefaultDirectory: DefaultDirectory(s.config_obj),
		EnvOverride:      os.Getenv(EnvDirectory) != "",
		LastVerify:       s.lastVerify,
		Verifying:        s.verifying,
		WriteErrors:      s.writeErrors,
		LastWriteError:   s.lastWriteError,
		Settings:         s.settings,
	}
	st.Directory, st.DirectorySource = s.resolveDirLocked()
	if !s.started && st.Reason == "" {
		st.Reason = "The audit log has not started."
	}
	if s.key != nil {
		pub := s.key.Public().(ed25519.PublicKey)
		st.KeyId = KeyID(pub)
		st.PublicKey = EncodePublicKey(pub)
	}
	if s.log != nil {
		st.Directory = s.log.Dir()
		st.Head = s.log.Head()
		st.Files, st.Bytes = dirStats(st.Directory)
	}
	st.Forward.Active = s.forwarder != nil
	st.Forward.Sent = s.fwdSent
	st.Forward.Dropped = s.fwdDropped
	st.Forward.LastError = s.fwdLastErr
	return st
}

// Dir returns the open directory, or an error when the log is closed.
func (s *Service) Dir() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		if s.reason != "" {
			return "", errors.New(s.reason)
		}
		return "", errors.New("The audit log is not open.")
	}
	return s.log.Dir(), nil
}

// RunVerify checks the whole chain against this server's key and the
// position recorded in the datastore. Problems are themselves audited
// and logged as errors.
func (s *Service) RunVerify() *Result {
	s.mu.Lock()
	if s.log == nil || s.verifying {
		r := s.lastVerify
		s.mu.Unlock()
		return r
	}
	s.verifying = true
	dir := s.log.Dir()
	head := s.log.Head()
	opts := VerifyOptions{
		TrustedKeys: []ed25519.PublicKey{s.key.Public().(ed25519.PublicKey)},
		UpTo:        head.Seq,
	}
	if a, ok := s.anchors[s.anchorKey(dir)]; ok && a.Seq <= head.Seq {
		a := a
		opts.Anchor = &a
	}
	s.mu.Unlock()

	r, err := Verify(dir, opts)
	if err != nil {
		r = &Result{Directory: dir, Problems: []Problem{{Severity: "error", Message: err.Error()}},
			Errors: 1, Checked: time.Now().Unix()}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifying = false
	wasOk := s.lastVerify == nil || s.lastVerify.Ok
	s.lastVerify = r
	if !r.Ok && s.log != nil && wasOk {
		msgs := []string{}
		for i, p := range r.Problems {
			if i == 10 {
				break
			}
			if p.Severity == "error" {
				msgs = append(msgs, p.Message)
			}
		}
		_ = s.appendLocked("", principalSelf, "audit_log_integrity_failed",
			map[string]interface{}{"errors": r.Errors, "problems": msgs})
		if s.config_obj != nil {
			logging.GetLogger(s.config_obj, &logging.FrontendComponent).
				Error("<red>Audit log integrity check failed</>: %v", strings.Join(msgs, "; "))
		}
	}
	return r
}

// SetSettings changes the directory and forwarding. A directory change
// closes the current chain with a final signed checkpoint and continues
// in the new directory (starting a new chain there, or continuing the
// one already there).
func (s *Service) SetSettings(ctx context.Context, in Settings, principal string) (Status, error) {
	in.Directory = strings.TrimSpace(in.Directory)
	in.Syslog.Server = strings.TrimSpace(in.Syslog.Server)
	in.Syslog.Protocol = strings.ToLower(strings.TrimSpace(in.Syslog.Protocol))
	if in.Syslog.Protocol == "" {
		in.Syslog.Protocol = syslogProtoUDP
	}
	switch in.Syslog.Protocol {
	case "udp", "tcp", "tls":
	default:
		return Status{}, errors.New("Protocol must be udp, tcp or tls.")
	}
	if in.Syslog.Enabled && !validHostPort(in.Syslog.Server) {
		return Status{}, errors.New("Enter the syslog server as host:port, for example siem.example.com:514.")
	}

	s.mu.Lock()
	if !s.started || s.config_obj == nil {
		s.mu.Unlock()
		return Status{}, errors.New("The audit log has not started.")
	}
	if in.Directory != "" && os.Getenv(EnvDirectory) != "" {
		s.mu.Unlock()
		return Status{}, fmt.Errorf("The directory is set by %v on the server.", EnvDirectory)
	}
	if err := ValidateDirectory(s.config_obj, in.Directory); err != nil {
		s.mu.Unlock()
		return Status{}, err
	}

	old := s.settings
	oldDir, _ := s.resolveDirLocked()
	in.UpdatedBy = principal
	in.Updated = time.Now().Unix()
	s.settings = in
	newDir, source := s.resolveDirLocked()

	if !samePath(oldDir, newDir) {
		if s.log != nil {
			// Test that the new directory works before leaving the old one.
			if err := os.MkdirAll(newDir, 0700); err != nil {
				s.settings = old
				s.mu.Unlock()
				return Status{}, fmt.Errorf("Cannot use %v: %v", newDir, err)
			}
		}
		var prevHead Head
		if s.log != nil {
			_ = s.appendLocked("", principal, "audit_log_moved",
				map[string]interface{}{"from": oldDir, "to": newDir})
			_ = s.log.Close("moved")
			s.anchors[s.anchorKey(oldDir)] = s.log.Head()
			prevHead = s.log.Head()
			s.log = nil
		}
		s.source = source
		if err := s.openLocked(newDir, map[string]interface{}{
			"previous_directory": oldDir,
			"previous_head":      prevHead,
			"moved_by":           principal,
		}); err != nil {
			// Go back to the old directory so nothing is lost.
			s.settings = old
			restoreErr := s.openLocked(oldDir, nil)
			s.mu.Unlock()
			if restoreErr != nil {
				return Status{}, fmt.Errorf("Cannot use %v (%v), and reopening %v failed: %v",
					newDir, err, oldDir, restoreErr)
			}
			return Status{}, fmt.Errorf("Cannot use %v: %v", newDir, err)
		}
	}

	if err := writeJSON(s.config_obj, settingsPath(), &s.settings); err != nil {
		s.mu.Unlock()
		return Status{}, err
	}
	if old.Syslog != in.Syslog {
		s.configureForwarderLocked()
	}
	if s.log != nil {
		_ = s.appendLocked("", principal, "audit_log_settings", map[string]interface{}{
			"directory":       newDir,
			"syslog_enabled":  in.Syslog.Enabled,
			"syslog_server":   in.Syslog.Server,
			"syslog_protocol": in.Syslog.Protocol,
		})
	}
	s.flushAnchorLocked()
	s.mu.Unlock()
	go s.RunVerify()
	return s.Status(), nil
}

func validHostPort(s string) bool {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 || strings.ContainsAny(s, " /\\@") {
		return false
	}
	for _, c := range s[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Query and Export run against the open directory.
func (s *Service) Query(f Filter) ([]*Entry, bool, error) {
	dir, err := s.Dir()
	if err != nil {
		return nil, false, err
	}
	return Query(dir, f)
}

func (s *Service) Export(f Filter, fn func(line []byte, e *Entry) error) error {
	dir, err := s.Dir()
	if err != nil {
		return err
	}
	return Export(dir, f, fn)
}

// resetForTests returns the service to its initial state.
func resetForTests() {
	global.mu.Lock()
	if global.log != nil {
		_ = global.log.Close("test")
	}
	global.mu.Unlock()
	global = &Service{}
}

// OfflineCheck is what the "audit verify" command found out from the
// server configuration.
type OfflineCheck struct {
	Directory string
	KeyId     string
	HasAnchor bool
}

// VerifyWithConfig verifies a log directory outside the server (the
// "audit verify" command). With a server configuration it checks the
// chain against the server's audit key and the position recorded in
// the datastore; dir defaults to the configured directory. pubKey
// (base64) adds a key to trust, for checking a copy elsewhere.
func VerifyWithConfig(ctx context.Context, config_obj *config_proto.Config,
	dir, pubKey string) (*Result, OfflineCheck, error) {
	info := OfflineCheck{}
	opts := VerifyOptions{}

	if pubKey != "" {
		pub, err := DecodePublicKey(pubKey)
		if err != nil {
			return nil, info, err
		}
		opts.TrustedKeys = append(opts.TrustedKeys, pub)
		info.KeyId = KeyID(pub)
	}

	var settings Settings
	var anchors anchorDoc
	if config_obj != nil && config_obj.Frontend != nil {
		if dek, err := secrets.GetDek(ctx, config_obj); err == nil {
			pub := DeriveKey(dek).Public().(ed25519.PublicKey)
			opts.TrustedKeys = append(opts.TrustedKeys, pub)
			info.KeyId = KeyID(pub)
		}
		_ = readJSON(config_obj, settingsPath(), &settings)
		_ = readJSON(config_obj, anchorPath(), &anchors)
	}

	if dir == "" {
		s := &Service{config_obj: config_obj, settings: settings}
		dir, _ = s.resolveDirLocked()
	}
	if dir == "" {
		return nil, info, errors.New("no audit log directory: pass --dir")
	}
	info.Directory = dir
	if anchors.Heads != nil {
		s := &Service{}
		if h, ok := anchors.Heads[s.anchorKey(dir)]; ok {
			opts.Anchor = &h
			info.HasAnchor = true
		}
	}
	r, err := Verify(dir, opts)
	return r, info, err
}
