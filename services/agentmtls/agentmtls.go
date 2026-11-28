// Package agentmtls checks agent certificates on the frontend (agent)
// port, so that only Atlantiraptor agents of this server get past the
// TLS handshake. Scanners and attackers on the internet are dropped
// before any server code reads what they send.
//
// What an agent presents (vql/networking/agent_identity.go): a
// certificate for its own communication key, the key its client ID
// is derived from. Brand new agents (GPO, Intune, MSI) sign it with
// the deployment certificate from their client configuration and send
// both.
//
// What the frontend accepts, in Enforce mode:
//
//   - an enrolled agent: the key is one this server enrolled (in any
//     org) and is not blocked;
//   - a new agent: an unknown key whose certificate is signed by the
//     current deployment certificate, while new enrollments are
//     allowed;
//   - an older agent that only presents the deployment certificate
//     itself (agents from before this feature that carry it in their
//     configuration, e.g. Linux and macOS agents that are not upgraded
//     automatically), while that is allowed.
//
// Warn mode asks for certificates and records what every agent
// presents, but lets everyone in; the console uses this to show which
// agents would be cut off before an administrator turns on Enforce.
// Off asks for nothing. Blocking an agent works in every mode: its
// messages are refused after decryption, and in Warn and Enforce its
// certificate is also refused in the handshake.
//
// Messages stay end-to-end encrypted with the agent's and server's
// keys as before; mTLS is an extra layer in front.
package agentmtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"google.golang.org/protobuf/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	crypto_utils "www.velocidex.com/golang/velociraptor/crypto/utils"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	ModeOff     = "off"
	ModeWarn    = "warn"
	ModeEnforce = "enforce"

	// DisableEnv turns agent mTLS off regardless of the saved mode.
	DisableEnv = "ATLANTIRAPTOR_DISABLE_AGENT_MTLS"

	// The common name of deployment certificates this service issues.
	DeploymentCommonName = "Atlantiraptor agent deployment"

	stateFileName = "atlantiraptor_agent_mtls.json"

	// Agents seen within this window count for readiness.
	readinessWindow = 24 * time.Hour
	// Forget agents not seen for this long.
	forgetAfter = 7 * 24 * time.Hour

	maxRejections = 50
	maxListed     = 200
)

// What an agent presented on its connection.
const (
	KindOwn    = "own"    // a certificate for its own, enrolled key
	KindNew    = "new"    // a new agent's certificate, signed by the deployment certificate
	KindLegacy = "legacy" // only the shared deployment certificate (older agent)
	KindNone   = "none"   // no certificate
	KindOther  = "other"  // a certificate that is not this agent's
)

type Settings struct {
	Mode string `json:"mode"`
	// Accept unknown agents with a certificate signed by the current
	// deployment certificate (new installs).
	AllowEnrollment bool `json:"allow_enrollment"`
	// Accept older agents that present only the deployment
	// certificate.
	AllowLegacy bool   `json:"allow_legacy"`
	UpdatedBy   string `json:"updated_by,omitempty"`
	Updated     int64  `json:"updated,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{
		Mode:            ModeWarn,
		AllowEnrollment: true,
		AllowLegacy:     true,
	}
}

func (self Settings) Validate() (Settings, error) {
	self.Mode = strings.ToLower(strings.TrimSpace(self.Mode))
	switch self.Mode {
	case ModeOff, ModeWarn, ModeEnforce:
	default:
		return self, fmt.Errorf("mode must be off, warn or enforce, not %q", self.Mode)
	}
	return self, nil
}

type BlockedAgent struct {
	ClientId string `json:"client_id"`
	OrgId    string `json:"org_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Reason   string `json:"reason,omitempty"`
	By       string `json:"by,omitempty"`
	Time     int64  `json:"time"`
}

// DeploymentCert is the certificate new agents carry in their client
// configuration. It is signed by the server's CA.
type DeploymentCert struct {
	CertPEM   string `json:"cert"`
	KeyPEM    string `json:"key"`
	Serial    string `json:"serial"`
	Created   int64  `json:"created"`
	CreatedBy string `json:"created_by,omitempty"`
	// The certificate came from the server configuration
	// (Client.Crypto.client_certificate) rather than being issued by
	// this service.
	FromConfig bool `json:"from_config,omitempty"`
}

type stateFile struct {
	Settings   Settings                 `json:"settings"`
	Deployment *DeploymentCert          `json:"deployment,omitempty"`
	Blocked    map[string]*BlockedAgent `json:"blocked,omitempty"`
}

type Rejection struct {
	Time     int64  `json:"time"`
	Remote   string `json:"remote"`
	ClientId string `json:"client_id,omitempty"`
	Reason   string `json:"reason"`
	Refused  bool   `json:"refused"`
}

type seenAgent struct {
	OrgId    string
	Kind     string
	LastSeen int64
	Remote   string
}

type Service struct {
	mu         sync.Mutex
	config_obj *config_proto.Config
	state_path string
	loaded     bool

	settings   Settings
	deployment *DeploymentCert
	blocked    map[string]*BlockedAgent

	// Parsed for the handshake.
	ca_cert           *x509.Certificate
	deployment_serial *big.Int

	// Why agent mTLS can not run on this server, if it can't.
	unavailable string
	frontend_up bool

	seen       map[string]*seenAgent
	rejections []Rejection
	handshakes map[string]int64

	keys *keyCache
	now  func() time.Time
}

var (
	global_mu sync.Mutex
	global    *Service
)

// Get returns the server's service. It exists even before Setup, in
// mode Off.
func Get() *Service {
	global_mu.Lock()
	defer global_mu.Unlock()
	if global == nil {
		global = newService(nil)
	}
	return global
}

func newService(config_obj *config_proto.Config) *Service {
	self := &Service{
		config_obj: config_obj,
		settings:   DefaultSettings(),
		blocked:    make(map[string]*BlockedAgent),
		seen:       make(map[string]*seenAgent),
		handshakes: make(map[string]int64),
		now:        time.Now,
	}
	self.keys = newKeyCache(self.lookupEnrolledKey)
	if config_obj != nil && config_obj.Datastore != nil &&
		config_obj.Datastore.Location != "" {
		self.state_path = filepath.Join(config_obj.Datastore.Location, stateFileName)
	}
	return self
}

// Setup loads the service for this server. It is called when the
// frontend starts and is safe to call more than once.
func Setup(config_obj *config_proto.Config) *Service {
	global_mu.Lock()
	defer global_mu.Unlock()
	if global != nil && global.loaded {
		return global
	}
	self := newService(config_obj)
	self.load()
	global = self
	return self
}

func (self *Service) logger() *logging.LogContext {
	config_obj := self.config_obj
	if config_obj == nil {
		config_obj = &config_proto.Config{}
	}
	return logging.GetLogger(config_obj, &logging.FrontendComponent)
}

func disabledByEnv() bool {
	v := strings.ToLower(os.Getenv(DisableEnv))
	return v != "" && v != "0" && v != "false"
}

func readState(path string) (*stateFile, error) {
	state := &stateFile{Settings: DefaultSettings()}
	if path == "" {
		return state, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("unreadable %v: %w", path, err)
	}
	if s, err := state.Settings.Validate(); err == nil {
		state.Settings = s
	} else {
		state.Settings = DefaultSettings()
	}
	return state, nil
}

func (self *Service) load() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.loaded = true

	state, err := readState(self.state_path)
	if err != nil {
		self.logger().Error("agent mTLS: %v", err)
		state = &stateFile{Settings: DefaultSettings()}
	}
	self.settings = state.Settings
	self.deployment = state.Deployment
	if state.Blocked != nil {
		self.blocked = state.Blocked
	}

	if self.config_obj == nil || self.config_obj.Client == nil ||
		self.config_obj.Client.CaCertificate == "" {
		self.unavailable = "the server has no CA certificate"
		return
	}
	ca, err := crypto_utils.ParseX509CertFromPemStr([]byte(self.config_obj.Client.CaCertificate))
	if err != nil {
		self.unavailable = "the CA certificate is unreadable"
		return
	}
	self.ca_cert = ca

	// The deployment certificate: the one issued by this service, or
	// the one the configuration wizard put in the client
	// configuration, or a new one.
	if self.deployment == nil {
		self.deployment = deploymentFromConfig(self.config_obj, ca)
	}
	if self.deployment == nil && self.config_obj.CA != nil &&
		self.config_obj.CA.PrivateKey != "" {
		d, err := issueDeploymentCert(self.config_obj, "server")
		if err != nil {
			self.logger().Error("agent mTLS: issuing a deployment certificate: %v", err)
		} else {
			self.deployment = d
		}
	}
	self.parseDeploymentLocked()
	if err := self.saveLocked(); err != nil {
		self.logger().Error("agent mTLS: saving %v: %v", self.state_path, err)
	}
}

func (self *Service) parseDeploymentLocked() {
	self.deployment_serial = nil
	if self.deployment == nil {
		return
	}
	cert, err := crypto_utils.ParseX509CertFromPemStr([]byte(self.deployment.CertPEM))
	if err != nil {
		return
	}
	self.deployment_serial = cert.SerialNumber
}

// deploymentFromConfig takes the client certificate the configuration
// wizard puts in Client.Crypto, if it is signed by our CA.
func deploymentFromConfig(config_obj *config_proto.Config,
	ca *x509.Certificate) *DeploymentCert {
	c := config_obj.GetClient().GetCrypto()
	if c == nil || c.ClientCertificate == "" || c.ClientCertificatePrivateKey == "" {
		return nil
	}
	cert, err := crypto_utils.ParseX509CertFromPemStr([]byte(c.ClientCertificate))
	if err != nil || cert.CheckSignatureFrom(ca) != nil {
		return nil
	}
	return &DeploymentCert{
		CertPEM:    c.ClientCertificate,
		KeyPEM:     c.ClientCertificatePrivateKey,
		Serial:     cert.SerialNumber.Text(16),
		Created:    cert.NotBefore.Unix(),
		FromConfig: true,
	}
}

// issueDeploymentCert makes a new deployment certificate signed by
// the server's CA.
func issueDeploymentCert(config_obj *config_proto.Config,
	principal string) (*DeploymentCert, error) {
	if config_obj.CA == nil || config_obj.CA.PrivateKey == "" ||
		config_obj.Client == nil {
		return nil, errors.New("the server configuration has no CA private key")
	}
	ca_cert, err := crypto_utils.ParseX509CertFromPemStr([]byte(config_obj.Client.CaCertificate))
	if err != nil {
		return nil, err
	}
	ca_key, err := crypto_utils.ParseRsaPrivateKeyFromPemStr([]byte(config_obj.CA.PrivateKey))
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   DeploymentCommonName,
			Organization: []string{"Atlantiraptor"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca_cert, &key.PublicKey, ca_key)
	if err != nil {
		return nil, err
	}
	return &DeploymentCert{
		CertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		Serial:    serial.Text(16),
		Created:   now.Unix(),
		CreatedBy: principal,
	}, nil
}

// saveLocked writes the state atomically. Call with mu held.
func (self *Service) saveLocked() error {
	if self.state_path == "" {
		return nil
	}
	data, err := json.MarshalIndent(stateFile{
		Settings:   self.settings,
		Deployment: self.deployment,
		Blocked:    self.blocked,
	}, "", " ")
	if err != nil {
		return err
	}
	tmp := self.state_path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, self.state_path)
}

// SetFrontendInfo records how the frontend listens. Agent mTLS needs
// the frontend on its own HTTPS port.
func (self *Service) SetFrontendInfo(unavailable string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.frontend_up = true
	if unavailable != "" {
		self.unavailable = unavailable
	}
}

// EffectiveMode is the mode the frontend uses now.
func (self *Service) EffectiveMode() string {
	self.mu.Lock()
	defer self.mu.Unlock()
	return self.effectiveModeLocked()
}

func (self *Service) effectiveModeLocked() string {
	if self.unavailable != "" || disabledByEnv() || !self.loaded {
		return ModeOff
	}
	return self.settings.Mode
}

func (self *Service) audit(ctx context.Context, principal, operation string,
	details *ordereddict.Dict) {
	if self.config_obj == nil {
		return
	}
	if err := services.LogAudit(ctx, self.config_obj, principal, operation, details); err != nil {
		self.logger().Error("agent mTLS audit %v: %v", operation, err)
	}
}

// ErrNotReady is returned when Enforce would cut off agents.
type ErrNotReady struct {
	Count int
}

func (self ErrNotReady) Error() string {
	return fmt.Sprintf("%d agent(s) seen in the last 24 hours would be refused in Enforce mode", self.Count)
}

// SetSettings saves new settings. Turning on Enforce (or turning off
// what lets current agents in) while agents seen recently would be
// refused fails with ErrNotReady unless force is set.
func (self *Service) SetSettings(ctx context.Context, s Settings,
	principal string, force bool) (Status, error) {
	s, err := s.Validate()
	if err != nil {
		return Status{}, err
	}

	self.mu.Lock()
	if !self.loaded {
		self.mu.Unlock()
		return Status{}, errors.New("the frontend is not running on this server")
	}
	if s.Mode == ModeEnforce && self.unavailable != "" {
		self.mu.Unlock()
		return Status{}, fmt.Errorf("agent mTLS is not available: %v", self.unavailable)
	}
	if s.Mode == ModeEnforce && !force {
		if n := self.wouldRefuseLocked(s); n > 0 {
			self.mu.Unlock()
			return Status{}, ErrNotReady{Count: n}
		}
	}
	old := self.settings
	s.UpdatedBy = principal
	s.Updated = self.now().Unix()
	self.settings = s
	err = self.saveLocked()
	self.mu.Unlock()
	if err != nil {
		return Status{}, err
	}

	self.audit(ctx, principal, "agent_mtls_settings", ordereddict.NewDict().
		Set("mode", s.Mode).
		Set("old_mode", old.Mode).
		Set("allow_enrollment", s.AllowEnrollment).
		Set("allow_legacy", s.AllowLegacy).
		Set("forced", force))
	self.logger().Info("agent mTLS: %v set mode %v (enrollment %v, older agents %v)",
		principal, s.Mode, s.AllowEnrollment, s.AllowLegacy)
	return self.Status(ctx), nil
}

// wouldRefuseLocked counts recently seen agents that the settings
// would refuse.
func (self *Service) wouldRefuseLocked(s Settings) int {
	cutoff := self.now().Add(-readinessWindow).Unix()
	count := 0
	for id, a := range self.seen {
		if a.LastSeen < cutoff {
			continue
		}
		if _, blocked := self.blocked[id]; blocked {
			continue
		}
		switch a.Kind {
		case KindOwn:
		case KindNew:
			// A new agent that has since enrolled presents KindOwn.
			if !s.AllowEnrollment {
				count++
			}
		case KindLegacy:
			if !s.AllowLegacy {
				count++
			}
		default:
			count++
		}
	}
	return count
}

// RotateDeployment issues a new deployment certificate. Agents that
// already enrolled keep working; new installs need a client
// configuration (MSI, Intune package, install script) made after the
// rotation, and older agents that present only the old deployment
// certificate are refused in Enforce mode.
func (self *Service) RotateDeployment(ctx context.Context, principal string) (Status, error) {
	self.mu.Lock()
	if self.config_obj == nil || !self.loaded {
		self.mu.Unlock()
		return Status{}, errors.New("the frontend is not running on this server")
	}
	d, err := issueDeploymentCert(self.config_obj, principal)
	if err != nil {
		self.mu.Unlock()
		return Status{}, err
	}
	old_serial := ""
	if self.deployment != nil {
		old_serial = self.deployment.Serial
	}
	self.deployment = d
	self.parseDeploymentLocked()
	err = self.saveLocked()
	self.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	self.audit(ctx, principal, "agent_mtls_rotate_deployment", ordereddict.NewDict().
		Set("old_serial", old_serial).
		Set("new_serial", d.Serial))
	return self.Status(ctx), nil
}

// DeploymentCertificate returns the current deployment certificate
// and key (PEM) for client configurations, or "" if there is none.
func (self *Service) DeploymentCertificate() (string, string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.deployment == nil {
		return "", ""
	}
	return self.deployment.CertPEM, self.deployment.KeyPEM
}

// WithDeploymentCert returns a copy of a client configuration about
// to be handed out (Deploy a client, `config client`, MSI and other
// packages) with the current deployment certificate in
// Client.Crypto, so new agents can enroll in Enforce mode with no
// manual steps. It reads the saved state, so it also works from the
// command line when the server is not running. The configuration is
// returned unchanged if there is nothing to add.
func WithDeploymentCert(full_config, client_config *config_proto.Config) *config_proto.Config {
	if client_config == nil || client_config.Client == nil {
		return client_config
	}
	cert, key := "", ""

	global_mu.Lock()
	s := global
	global_mu.Unlock()
	if s != nil && s.loaded {
		cert, key = s.DeploymentCertificate()
	} else if full_config != nil && full_config.Datastore != nil &&
		full_config.Datastore.Location != "" {
		state, err := readState(filepath.Join(full_config.Datastore.Location, stateFileName))
		if err == nil && state.Deployment != nil {
			cert, key = state.Deployment.CertPEM, state.Deployment.KeyPEM
		}
	}
	if cert == "" || key == "" {
		return client_config
	}
	result := proto.Clone(client_config).(*config_proto.Config)
	if result.Client.Crypto == nil {
		result.Client.Crypto = &config_proto.CryptoConfig{}
	}
	result.Client.Crypto.ClientCertificate = cert
	result.Client.Crypto.ClientCertificatePrivateKey = key
	return result
}

// Block refuses an agent from now on: in the handshake (Warn and
// Enforce) and for every message (all modes). Its open connections
// are closed.
func (self *Service) Block(ctx context.Context, client_id, org_id, hostname,
	reason, principal string) (Status, error) {
	base := utils.ClientIdFromSource(client_id)
	if !strings.HasPrefix(base, "C.") || len(base) < 4 || len(base) > 64 {
		return Status{}, fmt.Errorf("%q is not an agent's client ID", client_id)
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}

	self.mu.Lock()
	if !self.loaded {
		self.mu.Unlock()
		return Status{}, errors.New("the frontend is not running on this server")
	}
	self.blocked[base] = &BlockedAgent{
		ClientId: base,
		OrgId:    org_id,
		Hostname: hostname,
		Reason:   reason,
		By:       principal,
		Time:     self.now().Unix(),
	}
	err := self.saveLocked()
	self.mu.Unlock()
	if err != nil {
		return Status{}, err
	}

	self.disconnect(client_id, org_id)
	self.audit(ctx, principal, "agent_block", ordereddict.NewDict().
		Set("client_id", base).
		Set("org_id", org_id).
		Set("hostname", hostname).
		Set("reason", reason))
	self.logger().Info("agent mTLS: %v blocked agent %v (%v)", principal, base, hostname)
	return self.Status(ctx), nil
}

func (self *Service) Unblock(ctx context.Context, client_id, principal string) (Status, error) {
	base := utils.ClientIdFromSource(client_id)
	self.mu.Lock()
	entry, ok := self.blocked[base]
	if !ok {
		self.mu.Unlock()
		return Status{}, fmt.Errorf("agent %v is not blocked", base)
	}
	delete(self.blocked, base)
	err := self.saveLocked()
	self.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	self.audit(ctx, principal, "agent_unblock", ordereddict.NewDict().
		Set("client_id", base).
		Set("hostname", entry.Hostname))
	return self.Status(ctx), nil
}

// IsBlocked reports whether the agent (any org) is blocked.
func (self *Service) IsBlocked(client_id string) bool {
	base := utils.ClientIdFromSource(client_id)
	self.mu.Lock()
	defer self.mu.Unlock()
	_, ok := self.blocked[base]
	return ok
}

// disconnect closes an agent's open connections so it reconnects
// and is refused.
func (self *Service) disconnect(client_id, org_id string) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return
	}
	base := utils.ClientIdFromSource(client_id)
	for _, org := range org_manager.ListOrgs() {
		if org_id != "" && !utils.CompareOrgIds(org.Id, org_id) {
			continue
		}
		org_config, err := org_manager.GetOrgConfig(org.Id)
		if err != nil {
			continue
		}
		notifier, err := services.GetNotifier(org_config)
		if err != nil {
			continue
		}
		notifier.NotifyDirectListener(utils.ClientIdFromConfigObj(base, org_config))
	}
}

type Counts struct {
	Seen   int `json:"seen"`
	Own    int `json:"own"`
	New    int `json:"new"`
	Legacy int `json:"legacy"`
	None   int `json:"none"`
	Other  int `json:"other"`
}

type ListedAgent struct {
	ClientId string `json:"client_id"`
	OrgId    string `json:"org_id"`
	Hostname string `json:"hostname,omitempty"`
	Version  string `json:"version,omitempty"`
	Kind     string `json:"kind"`
	LastSeen int64  `json:"last_seen"`
	Remote   string `json:"remote,omitempty"`
}

type DeploymentInfo struct {
	Serial     string `json:"serial"`
	Created    int64  `json:"created"`
	CreatedBy  string `json:"created_by,omitempty"`
	FromConfig bool   `json:"from_config,omitempty"`
}

type Status struct {
	Settings      Settings `json:"settings"`
	EffectiveMode string   `json:"effective_mode"`
	Unavailable   string   `json:"unavailable,omitempty"`
	DisabledByEnv bool     `json:"disabled_by_env,omitempty"`
	FrontendUp    bool     `json:"frontend_up"`
	// The console listens on more than this computer
	// (GUI.bind_address is not a loopback address).
	ConsoleExposed bool            `json:"console_exposed,omitempty"`
	ConsoleBind    string          `json:"console_bind,omitempty"`
	Deployment     *DeploymentInfo `json:"deployment,omitempty"`
	Counts         Counts          `json:"counts"`
	// Agents seen in the last 24 hours that do not yet present their
	// own certificate.
	NotReady []ListedAgent `json:"not_ready"`
	// How many Enforce would refuse with the current settings.
	WouldRefuse   int            `json:"would_refuse"`
	Blocked       []BlockedAgent `json:"blocked"`
	Rejections    []Rejection    `json:"rejections"`
	WindowSeconds int64          `json:"window_seconds"`
}

func (self *Service) Status(ctx context.Context) Status {
	self.mu.Lock()
	s := Status{
		Settings:      self.settings,
		EffectiveMode: self.effectiveModeLocked(),
		Unavailable:   self.unavailable,
		DisabledByEnv: disabledByEnv(),
		FrontendUp:    self.frontend_up,
		NotReady:      []ListedAgent{},
		Blocked:       []BlockedAgent{},
		Rejections:    append([]Rejection{}, self.rejections...),
		WindowSeconds: int64(readinessWindow / time.Second),
	}
	if !self.loaded {
		s.Unavailable = "the frontend is not running on this server"
	}
	if gui := self.config_obj.GetGUI(); gui != nil && self.config_obj.GetServices().GetGuiServer() {
		s.ConsoleBind = fmt.Sprintf("%s:%d", gui.BindAddress, gui.BindPort)
		s.ConsoleExposed = !isLoopback(gui.BindAddress)
	}
	if d := self.deployment; d != nil {
		s.Deployment = &DeploymentInfo{Serial: d.Serial, Created: d.Created,
			CreatedBy: d.CreatedBy, FromConfig: d.FromConfig}
	}
	s.WouldRefuse = self.wouldRefuseLocked(Settings{
		Mode:            ModeEnforce,
		AllowEnrollment: self.settings.AllowEnrollment,
		AllowLegacy:     self.settings.AllowLegacy,
	})

	cutoff := self.now().Add(-readinessWindow).Unix()
	forget := self.now().Add(-forgetAfter).Unix()
	for id, a := range self.seen {
		if a.LastSeen < forget {
			delete(self.seen, id)
			continue
		}
		if a.LastSeen < cutoff {
			continue
		}
		s.Counts.Seen++
		switch a.Kind {
		case KindOwn:
			s.Counts.Own++
			continue
		case KindNew:
			s.Counts.New++
		case KindLegacy:
			s.Counts.Legacy++
		case KindNone:
			s.Counts.None++
		default:
			s.Counts.Other++
		}
		s.NotReady = append(s.NotReady, ListedAgent{
			ClientId: id, OrgId: a.OrgId, Kind: a.Kind,
			LastSeen: a.LastSeen, Remote: a.Remote,
		})
	}
	for _, b := range self.blocked {
		s.Blocked = append(s.Blocked, *b)
	}
	self.mu.Unlock()

	sort.Slice(s.NotReady, func(i, j int) bool {
		return s.NotReady[i].LastSeen > s.NotReady[j].LastSeen
	})
	if len(s.NotReady) > maxListed {
		s.NotReady = s.NotReady[:maxListed]
	}
	sort.Slice(s.Blocked, func(i, j int) bool { return s.Blocked[i].Time > s.Blocked[j].Time })
	for i := range s.NotReady {
		s.NotReady[i].Hostname, s.NotReady[i].Version =
			clientDetails(ctx, s.NotReady[i].OrgId, s.NotReady[i].ClientId)
	}
	return s
}

func isLoopback(addr string) bool {
	if strings.EqualFold(addr, "localhost") {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// clientDetails looks up an agent's host name and version.
func clientDetails(ctx context.Context, org_id, base string) (string, string) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return "", ""
	}
	org_config, err := org_manager.GetOrgConfig(org_id)
	if err != nil {
		return "", ""
	}
	client_info_manager, err := services.GetClientInfoManager(org_config)
	if err != nil {
		return "", ""
	}
	info, err := client_info_manager.Get(ctx, utils.ClientIdFromConfigObj(base, org_config))
	if err != nil || info == nil || info.ClientInfo == nil {
		return "", ""
	}
	return info.Hostname, info.ClientVersion
}
