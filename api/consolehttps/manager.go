package consolehttps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
)

// How long new settings stay on trial before they roll back by
// themselves. A variable so tests can shorten it.
var PendingTimeout = 10 * time.Minute

// Options come from the server when it starts the console.
type Options struct {
	// The console's HTTP handler (the same one the main console port uses).
	Handler http.Handler
	// Adds client certificate checks when the console requires them.
	ExtraTLS func(*tls.Config) error
	// Ports used by other parts of the server.
	Reserved []ReservedPort
	// The console address from the config file, which always keeps working.
	RecoveryURL string
	// Path of the console page under the server's base path.
	AppPath string
	// The sign-in method and public_url, for advice on the page.
	Authenticator string
	PublicURL     string
	// Why the feature can't be used on this server, if it can't.
	Unavailable string
	// A risk the administrator must accept before turning it on, such
	// as exposing a console that otherwise only listens on localhost.
	ApplyWarning string
}

// CertState is the certificate that the extra listener is serving.
type CertState struct {
	Status string    `json:"status"` // ready, issuing, failed
	Error  string    `json:"error,omitempty"`
	Info   *CertInfo `json:"info,omitempty"`
}

// Pending is a setting on trial.
type Pending struct {
	Settings Settings  `json:"settings"`
	Expires  int64     `json:"expires"`
	By       string    `json:"by"`
	Previous *Settings `json:"-"`
}

// View is what the console page shows.
type View struct {
	Available     bool      `json:"available"`
	Unavailable   string    `json:"unavailable_reason,omitempty"`
	Active        Settings  `json:"active"`
	Pending       *Pending  `json:"pending,omitempty"`
	Serving       string    `json:"serving"` // "", "active" or "pending"
	URL           string    `json:"url,omitempty"`
	Cert          CertState `json:"cert"`
	RecoveryURL   string    `json:"recovery_url"`
	Authenticator string    `json:"authenticator,omitempty"`
	PublicURL     string    `json:"public_url,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Reserved      []uint32  `json:"reserved_ports,omitempty"`
}

// ApplyError carries a user-facing reason. Code "needs_confirmation"
// means the request may be repeated with confirmation.
type ApplyError struct {
	Code     string
	Message  string
	Warnings []string
}

func (e *ApplyError) Error() string { return e.Message }

type running struct {
	id       int
	settings Settings
	key      []byte
	srv      *http.Server
	redirect *http.Server
	acme     *autocert.Manager
}

// Manager runs the extra console listener. One per server process.
type Manager struct {
	mu         sync.Mutex
	ctx        context.Context
	config_obj *config_proto.Config
	opts       Options
	started    bool

	active    Settings
	activeKey []byte
	pending   *Pending
	timer     *time.Timer

	cur       *running
	nextID    int
	cert      CertState
	lastError string

	// Tests point these at fakes.
	listen     func(network, addr string) (net.Listener, error)
	acmeClient *acme.Client
	issueHello func(host string) *tls.ClientHelloInfo
}

var global = &Manager{}

// Get returns the server's manager.
func Get() *Manager { return global }

// NewManager makes a separate manager (tests).
func NewManager() *Manager { return &Manager{} }

func (m *Manager) logger() *logging.LogContext {
	return logging.GetLogger(m.config_obj, &logging.GUIComponent)
}

// Start loads the confirmed settings and, if enabled, starts serving.
// Problems are logged and shown on the console page; they never stop
// the server, because the main console address doesn't depend on this.
func (m *Manager) Start(ctx context.Context, wg *sync.WaitGroup,
	config_obj *config_proto.Config, opts Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return
	}
	m.started = true
	m.ctx, m.config_obj, m.opts = ctx, config_obj, opts
	if m.listen == nil {
		m.listen = net.Listen
	}

	if opts.Unavailable != "" {
		return
	}
	s, key, err := load(ctx, config_obj)
	if err != nil {
		m.lastError = "The saved HTTPS settings could not be read: " + err.Error()
		m.logger().Error("console https: %v", m.lastError)
	} else {
		m.active, m.activeKey = s, key
		if s.Enabled {
			if err := m.startLocked(s, key); err != nil {
				m.lastError = err.Error()
				m.logger().Error("console https: %v", err)
			}
		}
	}

	if wg != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.timer != nil {
				m.timer.Stop()
			}
			m.stopLocked()
		}()
	}
}

func originOf(s Settings) string {
	host := s.Hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if s.Port != 443 && s.Port != 0 {
		host += ":" + strconv.Itoa(int(s.Port))
	}
	return "https://" + host
}

func (m *Manager) consoleURL(s Settings) string {
	if !s.Enabled || s.Hostname == "" {
		return ""
	}
	path := m.opts.AppPath
	if path == "" {
		path = "/app/index.html"
	}
	return originOf(s) + path
}

// Status reports the current state.
func (m *Manager) Status() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked()
}

func (m *Manager) viewLocked() View {
	v := View{
		Available:     m.started && m.opts.Unavailable == "",
		Unavailable:   m.opts.Unavailable,
		Active:        m.active,
		RecoveryURL:   m.opts.RecoveryURL,
		Authenticator: m.opts.Authenticator,
		PublicURL:     m.opts.PublicURL,
		LastError:     m.lastError,
		Cert:          m.cert,
	}
	if !m.started {
		v.Unavailable = "HTTPS settings are only available on the server that runs the console."
	}
	for _, r := range m.opts.Reserved {
		if r.Port != 0 {
			v.Reserved = append(v.Reserved, r.Port)
		}
	}
	if m.pending != nil {
		p := *m.pending
		v.Pending = &p
	}
	if m.cur != nil {
		v.URL = m.consoleURL(m.cur.settings)
		v.Serving = "active"
		if m.pending != nil {
			v.Serving = "pending"
		}
		if m.cur.settings.Mode == ModeCertificate {
			if chain, err := ParseChain(m.cur.settings.CertPEM); err == nil {
				info := Describe(chain, m.cur.settings.Hostname)
				v.Cert = CertState{Status: "ready", Info: &info}
			}
		}
	} else {
		v.Cert = CertState{}
	}
	return v
}

func (m *Manager) checkStarted() error {
	if !m.started {
		return &ApplyError{Code: "unavailable", Message: "HTTPS settings are only available on the server that runs the console."}
	}
	if m.opts.Unavailable != "" {
		return &ApplyError{Code: "unavailable", Message: m.opts.Unavailable}
	}
	return nil
}

// Apply validates new settings and starts serving them on trial. They
// roll back after PendingTimeout unless confirmed.
func (m *Manager) Apply(ctx context.Context, principal string, s Settings, up Upload,
	keepCertificate, confirmed bool) (View, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkStarted(); err != nil {
		return m.viewLocked(), nil, err
	}

	s, warnings, err := ValidateSettings(s, m.opts.Reserved)
	if err != nil {
		return m.viewLocked(), nil, &ApplyError{Code: "invalid", Message: err.Error()}
	}

	var key []byte
	if s.Mode == ModeCertificate {
		if up.Empty() {
			if !keepCertificate {
				return m.viewLocked(), nil, &ApplyError{Code: "invalid", Message: "Upload the certificate and its private key."}
			}
			// Reuse the certificate being served or confirmed.
			src, srcKey := m.active, m.activeKey
			if m.cur != nil && m.cur.settings.Mode == ModeCertificate {
				src, srcKey = m.cur.settings, m.cur.key
			}
			if src.Mode != ModeCertificate || src.CertPEM == "" || len(srcKey) == 0 {
				return m.viewLocked(), nil, &ApplyError{Code: "invalid", Message: "There is no saved certificate to keep. Upload the certificate and its private key."}
			}
			s.CertPEM, key = src.CertPEM, srcKey
		} else {
			certPEM, keyPEM, err := ParseUpload(up)
			if err != nil {
				return m.viewLocked(), nil, &ApplyError{Code: "invalid", Message: err.Error()}
			}
			s.CertPEM, key = certPEM, keyPEM
		}
		_, certWarnings, err := CheckCertificate(s.CertPEM, s.Hostname)
		if err != nil {
			return m.viewLocked(), nil, &ApplyError{Code: "invalid", Message: err.Error()}
		}
		warnings = append(warnings, certWarnings...)
	}
	if m.opts.ApplyWarning != "" {
		warnings = append(warnings, m.opts.ApplyWarning)
	}
	if len(warnings) > 0 && !confirmed {
		return m.viewLocked(), warnings, &ApplyError{
			Code: "needs_confirmation", Message: strings.Join(warnings, " "), Warnings: warnings}
	}

	s.Updated, s.UpdatedBy = time.Now().Unix(), principal

	// Remember what to roll back to: the confirmed settings.
	prev := m.active
	prevRunning := m.cur != nil

	m.stopLocked()
	if err := m.startLocked(s, key); err != nil {
		// Put back whatever was serving before.
		if prevRunning && prev.Enabled {
			if err2 := m.startLocked(prev, m.activeKey); err2 != nil {
				m.lastError = err2.Error()
			}
		}
		m.auditLocked(ctx, principal, "console_https_apply_failed", ordereddict.NewDict().
			Set("hostname", s.Hostname).Set("port", s.Port).Set("mode", s.Mode).Set("error", err.Error()))
		return m.viewLocked(), warnings, &ApplyError{Code: "listen_failed", Message: err.Error()}
	}
	m.lastError = ""

	if m.timer != nil {
		m.timer.Stop()
	}
	m.pending = &Pending{
		Settings: s, By: principal, Previous: &prev,
		Expires: time.Now().Add(PendingTimeout).Unix(),
	}
	m.pending.Settings.CertPEM = s.CertPEM
	id := m.cur.id
	m.timer = time.AfterFunc(PendingTimeout, func() { m.expire(id) })

	m.auditLocked(ctx, principal, "console_https_apply", ordereddict.NewDict().
		Set("hostname", s.Hostname).Set("port", s.Port).Set("mode", s.Mode).
		Set("redirect_http", s.RedirectHTTP).Set("warnings_confirmed", warnings).
		Set("expires", m.pending.Expires))
	return m.viewLocked(), warnings, nil
}

// Confirm keeps the settings on trial.
func (m *Manager) Confirm(ctx context.Context, principal string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkStarted(); err != nil {
		return m.viewLocked(), err
	}
	if m.pending == nil || m.cur == nil {
		return m.viewLocked(), &ApplyError{Code: "nothing_pending", Message: "There are no new settings waiting for confirmation. They may have rolled back already."}
	}
	if m.cur.settings.Mode == ModeLetsEncrypt && m.cert.Status != "ready" {
		return m.viewLocked(), &ApplyError{Code: "not_ready", Message: "Wait until Let's Encrypt has issued the certificate and the new address opens in your browser."}
	}
	s := m.cur.settings
	if err := save(ctx, m.config_obj, s, m.cur.key); err != nil {
		return m.viewLocked(), &ApplyError{Code: "save_failed", Message: "The settings could not be saved: " + err.Error()}
	}
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.active, m.activeKey = s, m.cur.key
	m.pending = nil
	m.auditLocked(ctx, principal, "console_https_confirm", ordereddict.NewDict().
		Set("hostname", s.Hostname).Set("port", s.Port).Set("mode", s.Mode))
	return m.viewLocked(), nil
}

// Revert drops the settings on trial and goes back to the confirmed ones.
func (m *Manager) Revert(ctx context.Context, principal string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkStarted(); err != nil {
		return m.viewLocked(), err
	}
	if m.pending == nil {
		return m.viewLocked(), &ApplyError{Code: "nothing_pending", Message: "There are no new settings to undo."}
	}
	m.rollbackLocked()
	m.auditLocked(ctx, principal, "console_https_revert", ordereddict.NewDict())
	return m.viewLocked(), nil
}

// Disable stops the extra listener and forgets the settings. The
// console stays on its original address.
func (m *Manager) Disable(ctx context.Context, principal string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkStarted(); err != nil {
		return m.viewLocked(), err
	}
	off := Settings{Updated: time.Now().Unix(), UpdatedBy: principal}
	if err := save(ctx, m.config_obj, off, nil); err != nil {
		return m.viewLocked(), &ApplyError{Code: "save_failed", Message: "The settings could not be saved: " + err.Error()}
	}
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.pending = nil
	m.stopLocked()
	prev := m.active
	m.active, m.activeKey = off, nil
	m.lastError = ""
	m.auditLocked(ctx, principal, "console_https_disable", ordereddict.NewDict().
		Set("hostname", prev.Hostname).Set("port", prev.Port))
	return m.viewLocked(), nil
}

func (m *Manager) expire(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil || m.cur == nil || m.cur.id != id {
		return
	}
	m.logger().Info("console https: new settings were not confirmed in time; rolling back")
	m.rollbackLocked()
	m.auditLocked(m.ctx, "system", "console_https_rollback", ordereddict.NewDict().
		Set("reason", "not confirmed in time"))
}

func (m *Manager) rollbackLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.pending = nil
	m.stopLocked()
	m.lastError = ""
	if m.active.Enabled {
		if err := m.startLocked(m.active, m.activeKey); err != nil {
			m.lastError = err.Error()
		}
	}
}

func (m *Manager) auditLocked(ctx context.Context, principal, op string, details *ordereddict.Dict) {
	if m.config_obj == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := services.LogAudit(ctx, m.config_obj, principal, op, details); err != nil {
		m.logger().Info("console https: %v by %v: %v", op, principal, details)
	}
}

func listenProblem(addr string, port uint32, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied") || strings.Contains(msg, "access permissions"):
		return fmt.Errorf("This server isn't allowed to open port %d (%s). On Linux, allow it with "+
			"`setcap cap_net_bind_service=+ep` on the server binary, or AmbientCapabilities=CAP_NET_BIND_SERVICE in its service unit.", port, addr)
	case strings.Contains(msg, "address already in use") || strings.Contains(msg, "Only one usage"):
		return fmt.Errorf("Another program on this server already uses port %d (for example IIS or another web server). Stop it or choose another port.", port)
	case strings.Contains(msg, "cannot assign requested address") || strings.Contains(msg, "not valid in its context"):
		return fmt.Errorf("%s is not an address of this server.", addr)
	}
	return fmt.Errorf("Could not listen on %s: %v", addr, err)
}

func (m *Manager) startLocked(s Settings, key []byte) error {
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	var mgr *autocert.Manager
	switch s.Mode {
	case ModeCertificate:
		pair, err := tls.X509KeyPair([]byte(s.CertPEM), key)
		if err != nil {
			return fmt.Errorf("The saved certificate could not be loaded: %v", err)
		}
		tlsConf.Certificates = []tls.Certificate{pair}
	case ModeLetsEncrypt:
		mgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Hostname),
			Cache:      acmeCache{config_obj: m.config_obj},
			Email:      s.Email,
			Client:     m.acmeClient,
		}
		tlsConf.GetCertificate = mgr.GetCertificate
		tlsConf.NextProtos = append(tlsConf.NextProtos, acme.ALPNProto)
	default:
		return errors.New("unknown certificate mode")
	}
	if m.opts.ExtraTLS != nil {
		if err := m.opts.ExtraTLS(tlsConf); err != nil {
			return err
		}
	}

	port := s.Port
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(s.BindAddress, strconv.Itoa(int(port)))
	ln, err := m.listen("tcp", addr)
	if err != nil {
		return listenProblem(addr, port, err)
	}

	m.nextID++
	r := &running{id: m.nextID, settings: s, key: key, acme: mgr}
	errLog := logging.NewPlainLogger(m.config_obj, &logging.GUIComponent)
	r.srv = &http.Server{
		Handler:           m.opts.Handler,
		TLSConfig:         tlsConf,
		ErrorLog:          errLog,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       500 * time.Second,
		WriteTimeout:      900 * time.Second,
		IdleTimeout:       150 * time.Second,
	}

	if s.RedirectHTTP {
		addr80 := net.JoinHostPort(s.BindAddress, "80")
		ln80, err := m.listen("tcp", addr80)
		if err != nil {
			_ = ln.Close()
			return listenProblem(addr80, 80, err)
		}
		var h http.Handler = redirectHandler(originOf(s))
		if mgr != nil {
			h = mgr.HTTPHandler(h)
		}
		r.redirect = &http.Server{Handler: h, ErrorLog: errLog,
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			if err := r.redirect.Serve(ln80); err != nil && err != http.ErrServerClosed {
				m.logger().Error("console https: redirect listener: %v", err)
			}
		}()
	}

	go func() {
		if err := r.srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			m.logger().Error("console https: %v", err)
		}
	}()

	m.cur = r
	m.logger().Info("console https: serving the console at <green>%s</>", m.consoleURL(s))
	if mgr != nil {
		m.cert = CertState{Status: "issuing"}
		go m.issue(r)
	} else {
		m.cert = CertState{Status: "ready"}
	}
	return nil
}

// issue asks Let's Encrypt for the certificate straight away, so the
// administrator sees success or the reason for failure on the page
// instead of in their first browser visit.
func (m *Manager) issue(r *running) {
	hello := &tls.ClientHelloInfo{
		ServerName: r.settings.Hostname,
		// Look like a modern browser so the certificate that browsers
		// will ask for (ECDSA) is the one issued.
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
	if m.issueHello != nil {
		hello = m.issueHello(r.settings.Hostname)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	type res struct {
		cert *tls.Certificate
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := r.acme.GetCertificate(hello)
		ch <- res{c, err}
	}()
	var out res
	select {
	case out = <-ch:
	case <-ctx.Done():
		out.err = errors.New("timed out waiting for Let's Encrypt")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != r {
		return
	}
	if out.err != nil {
		m.cert = CertState{Status: "failed", Error: leProblem(r.settings.Hostname, out.err)}
		m.logger().Error("console https: Let's Encrypt: %v", out.err)
		return
	}
	st := CertState{Status: "ready"}
	if out.cert != nil {
		if chain := leafChain(out.cert); len(chain) > 0 {
			info := Describe(chain, r.settings.Hostname)
			st.Info = &info
		}
	}
	m.cert = st
}

func leProblem(host string, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rateLimited") || strings.Contains(msg, "too many"):
		return "Let's Encrypt refused because of its rate limits: " + msg + ". Wait before trying again, or upload a certificate."
	case strings.Contains(msg, "Timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "Connection refused") || strings.Contains(msg, "connection"):
		return fmt.Sprintf("Let's Encrypt could not reach %s on port 443 (or 80). Check that the host name points to this server's public address and that the firewall lets the ports in. Details: %s", host, msg)
	case strings.Contains(msg, "NXDOMAIN") || strings.Contains(msg, "DNS"):
		return fmt.Sprintf("%s does not resolve in public DNS. Create the DNS record first. Details: %s", host, msg)
	}
	return "Let's Encrypt could not issue the certificate: " + msg
}

func (m *Manager) stopLocked() {
	r := m.cur
	if r == nil {
		return
	}
	m.cur = nil
	m.cert = CertState{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.srv.SetKeepAlivesEnabled(false)
	if err := r.srv.Shutdown(ctx); err != nil {
		_ = r.srv.Close()
	}
	if r.redirect != nil {
		if err := r.redirect.Shutdown(ctx); err != nil {
			_ = r.redirect.Close()
		}
	}
}

func redirectHandler(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always to the configured host name, never the Host header,
		// so this can't be used as an open redirect.
		http.Redirect(w, r, base+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func leafChain(c *tls.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, der := range c.Certificate {
		x, err := x509.ParseCertificate(der)
		if err != nil {
			return nil
		}
		out = append(out, x)
	}
	return out
}
