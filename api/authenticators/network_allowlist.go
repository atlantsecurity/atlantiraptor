package authenticators

// Network allowlists, managed by administrators at run time (Admin >
// Network access) and stored in the root org's file store. Separate
// lists apply to the console (GUI and its API) and to the integration
// REST API (/api/atl/v1). Each list is off until enabled.
//
// Lockout protection:
//   - Requests from this machine (loopback) are always allowed.
//   - ATLANTIRAPTOR_DISABLE_ALLOWLIST=1 turns all lists off (restart the
//     server with it set to recover).
//   - Saving a list that excludes your own address needs confirmation.
//
// Denied requests are logged and written to the audit log (at most once
// a minute per address and area).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
)

const (
	AllowlistConsole = "console"
	AllowlistAPI     = "api"

	maxAllowlistEntries = 500
	allowlistCacheTTL   = 5 * time.Second
	breakGlassEnv       = "ATLANTIRAPTOR_DISABLE_ALLOWLIST"
)

type NetworkList struct {
	Enabled bool     `json:"enabled"`
	Entries []string `json:"entries"`
}

type NetworkPolicy struct {
	Console   NetworkList `json:"console"`
	API       NetworkList `json:"api"`
	Updated   int64       `json:"updated,omitempty"`
	UpdatedBy string      `json:"updated_by,omitempty"`
}

var (
	netPolicyMu      sync.Mutex
	netPolicyCache   *compiledPolicy
	netPolicyFetched time.Time
)

type compiledPolicy struct {
	policy  NetworkPolicy
	console []*net.IPNet
	api     []*net.IPNet
	err     error
}

func networkPolicyPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_network").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func AllowlistBreakGlass() bool {
	return os.Getenv(breakGlassEnv) == "1"
}

// ParseNetworkEntry accepts a single IP address or a CIDR range.
func ParseNetworkEntry(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty entry")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid address range", s)
		}
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%q is not a valid IP address or range", s)
	}
	bits := 128
	if ip.To4() != nil {
		ip, bits = ip.To4(), 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

func compileList(l NetworkList) ([]*net.IPNet, []string, error) {
	if len(l.Entries) > maxAllowlistEntries {
		return nil, nil, fmt.Errorf("at most %d entries", maxAllowlistEntries)
	}
	nets, clean := []*net.IPNet{}, []string{}
	for _, e := range l.Entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		n, err := ParseNetworkEntry(e)
		if err != nil {
			return nil, nil, err
		}
		nets = append(nets, n)
		clean = append(clean, e)
	}
	return nets, clean, nil
}

// ValidateNetworkPolicy normalises a policy and checks every entry.
func ValidateNetworkPolicy(p NetworkPolicy) (NetworkPolicy, error) {
	_, c, err := compileList(p.Console)
	if err != nil {
		return p, fmt.Errorf("console: %w", err)
	}
	_, a, err := compileList(p.API)
	if err != nil {
		return p, fmt.Errorf("API: %w", err)
	}
	p.Console.Entries, p.API.Entries = c, a
	return p, nil
}

func loadNetworkPolicy(root *config_proto.Config) *compiledPolicy {
	netPolicyMu.Lock()
	defer netPolicyMu.Unlock()
	if netPolicyCache != nil && time.Since(netPolicyFetched) < allowlistCacheTTL {
		return netPolicyCache
	}
	result := &compiledPolicy{}
	p, err := readNetworkPolicy(root)
	if err != nil {
		// Can't read the policy: keep using the last good one, or, with
		// none, fail closed for everything but loopback.
		if netPolicyCache != nil && netPolicyCache.err == nil {
			netPolicyFetched = time.Now()
			return netPolicyCache
		}
		result.err = err
	} else {
		result.policy = p
		result.console, _, _ = compileList(p.Console)
		result.api, _, _ = compileList(p.API)
	}
	netPolicyCache, netPolicyFetched = result, time.Now()
	return result
}

func readNetworkPolicy(root *config_proto.Config) (NetworkPolicy, error) {
	p := NetworkPolicy{}
	fs := file_store.GetFileStore(root)
	if fs == nil {
		return p, errors.New("file store unavailable")
	}
	if _, err := fs.StatFile(networkPolicyPath()); err != nil {
		if isNotExist(err) {
			return p, nil
		}
		return p, err
	}
	reader, err := fs.ReadFile(networkPolicyPath())
	if err != nil {
		return p, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return p, err
	}
	if len(data) == 0 {
		// The file exists but is empty (e.g. an interrupted write):
		// treat it as unreadable, never as "no lists".
		return p, errors.New("network policy file is empty")
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	return ValidateNetworkPolicy(p)
}

// GetNetworkPolicy returns the saved policy (for the admin screen).
func GetNetworkPolicy(root *config_proto.Config) (NetworkPolicy, error) {
	c := loadNetworkPolicy(root)
	return c.policy, c.err
}

// SaveNetworkPolicy validates and stores the policy.
func SaveNetworkPolicy(root *config_proto.Config, p NetworkPolicy, by string) (NetworkPolicy, error) {
	p, err := ValidateNetworkPolicy(p)
	if err != nil {
		return p, err
	}
	p.Updated, p.UpdatedBy = time.Now().Unix(), by
	data, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	fs := file_store.GetFileStore(root)
	if fs == nil {
		return p, errors.New("file store unavailable")
	}
	netPolicyMu.Lock()
	defer netPolicyMu.Unlock()
	writer, err := fs.WriteFile(networkPolicyPath())
	if err != nil {
		return p, err
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return p, err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return p, err
	}
	if err := writer.Close(); err != nil {
		return p, err
	}
	compiled := &compiledPolicy{policy: p}
	compiled.console, _, _ = compileList(p.Console)
	compiled.api, _, _ = compileList(p.API)
	netPolicyCache, netPolicyFetched = compiled, time.Now()
	return p, nil
}

// ClientIP is the address a request came from. When the server is
// configured to sit behind a proxy (GUI.forwarded_proxy_header), the
// last entry of the last header line is used: the one the proxy itself
// added. A configured but missing or unparsable header gives no address,
// so the request is refused by any enabled list. Direct access to the
// server port must then be blocked, or the header could be forged.
func ClientIP(config_obj *config_proto.Config, r *http.Request) net.IP {
	if config_obj != nil && config_obj.GUI != nil && config_obj.GUI.ForwardedProxyHeader != "" {
		lines := r.Header.Values(config_obj.GUI.ForwardedProxyHeader)
		if len(lines) == 0 {
			return nil
		}
		parts := strings.Split(lines[len(lines)-1], ",")
		return parseHostIP(strings.TrimSpace(parts[len(parts)-1]))
	}
	return parseHostIP(r.RemoteAddr)
}

// parseHostIP accepts "ip", "ip:port", "[ipv6]" and "[ipv6]:port".
func parseHostIP(s string) net.IP {
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(s, "[]"))
}

// BehindSameHostProxy reports a likely misconfiguration: requests arrive
// from loopback and no forwarded header is configured, so every client
// looks local and the lists can't tell them apart.
func BehindSameHostProxy(config_obj *config_proto.Config, ip net.IP) bool {
	return ip != nil && ip.IsLoopback() &&
		(config_obj == nil || config_obj.GUI == nil || config_obj.GUI.ForwardedProxyHeader == "")
}
func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowedByNetworkPolicy reports whether ip may use the given area.
func AllowedByNetworkPolicy(root *config_proto.Config, area string, ip net.IP) bool {
	if ip != nil && ip.IsLoopback() {
		return true
	}
	if AllowlistBreakGlass() {
		return true
	}
	c := loadNetworkPolicy(root)
	if c.err != nil {
		return false
	}
	list, nets := c.policy.Console, c.console
	if area == AllowlistAPI {
		list, nets = c.policy.API, c.api
	}
	if !list.Enabled {
		return true
	}
	return ip != nil && ipInNets(ip, nets)
}

// IPAllowedByEntries checks an address against a list of entries (used
// for per-key allowlists). An empty list allows everything.
func IPAllowedByEntries(ip net.IP, entries []string) bool {
	if len(entries) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, e := range entries {
		if n, err := ParseNetworkEntry(e); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	deniedMu        sync.Mutex
	deniedSeen      = map[string]time.Time{}
	deniedBudget    = 30.0 // log events, refilled at 30 a minute
	deniedLast      time.Time
	deniedSuppressd int
)

// deniedKey groups IPv6 addresses by /64 so one network can't flood
// the log with many addresses.
func deniedKey(area string, ip net.IP) string {
	if ip == nil {
		return area + "|unknown"
	}
	if ip.To4() == nil {
		return area + "|" + ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return area + "|" + ip.String()
}

// LogNetworkDenied logs and audits a refused request: at most once a
// minute for each address (or IPv6 /64) and area, and at most 30 events
// a minute in total; the rest are counted and reported with the next one.
func LogNetworkDenied(root *config_proto.Config, area, what string, ip net.IP, r *http.Request) {
	now := time.Now()
	key := deniedKey(area, ip)
	deniedMu.Lock()
	if now.Sub(deniedSeen[key]) < time.Minute {
		deniedMu.Unlock()
		return
	}
	deniedBudget += now.Sub(deniedLast).Minutes() * 30
	if deniedBudget > 30 {
		deniedBudget = 30
	}
	deniedLast = now
	if deniedBudget < 1 {
		deniedSuppressd++
		deniedMu.Unlock()
		return
	}
	deniedBudget--
	if len(deniedSeen) >= 10000 {
		for k, t := range deniedSeen {
			if now.Sub(t) >= time.Minute {
				delete(deniedSeen, k)
			}
		}
	}
	if len(deniedSeen) < 10000 {
		deniedSeen[key] = now
	}
	suppressed := deniedSuppressd
	deniedSuppressd = 0
	deniedMu.Unlock()

	ipText := "unknown"
	if ip != nil {
		ipText = ip.String()
	}
	logging.GetLogger(root, &logging.FrontendComponent).
		Info("network allowlist: refused %v from %v (%v %q), %d similar events not logged",
			area, ipText, r.Method, r.URL.Path, suppressed)
	details := ordereddict.NewDict().Set("area", area).Set("what", what).Set("ip", ipText).
		Set("path", r.URL.Path).Set("method", r.Method).Set("suppressed_since_last", suppressed)
	go func() {
		_ = services.LogAudit(context.Background(), root, "network-allowlist", "network_denied", details)
	}()
}
func networkArea(config_obj *config_proto.Config, path string) string {
	base := ""
	if config_obj != nil && config_obj.GUI != nil {
		base = strings.TrimRight(config_obj.GUI.BasePath, "/")
	}
	if strings.HasPrefix(path, base+"/api/atl/v1/") {
		return AllowlistAPI
	}
	return AllowlistConsole
}

// networkAllowlistGate enforces the run-time allowlists in front of a
// handler.
func networkAllowlistGate(config_obj *config_proto.Config, parent http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		root, err := rootConfig()
		if err != nil {
			root = config_obj
		}
		ip := ClientIP(config_obj, r)
		area := networkArea(config_obj, r.URL.Path)
		if !AllowedByNetworkPolicy(root, area, ip) {
			LogNetworkDenied(root, area, "network allowlist", ip, r)
			http.Error(w, "Access from this network address is not allowed.", http.StatusForbidden)
			return
		}
		parent.ServeHTTP(w, r)
	}
}
