package authenticators

// Remembered addresses: once a user passes the second factor from an
// IP address, later sign ins by that user from the same address skip
// the code for a while (MFAPolicy.RememberIPDays, 30 days by default).
//
// The addresses live in the user's 2FA record on the server, so they
// survive browser restarts, cleared cookies and server restarts. Each
// entry carries the record generation, so anything that revokes 2FA
// sessions (password change, factor reset or disable) also forgets
// every remembered address. The password is still checked on every
// request; only the code is skipped.

import (
	"net"
	"net/http"
	"sort"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

const (
	DefaultRememberIPDays = 30
	MaxRememberIPDays     = 365
	// Most remembered addresses kept per user; the oldest go first.
	maxTrustedIPs = 32
)

type TrustedIP struct {
	// When the second factor was last passed from this address.
	Passed int64 `json:"passed"`
	// Record generation at that time.
	Generation int64 `json:"generation"`
}

// rememberIPWindow is how long a passed check is remembered for an
// address under the policy, or 0 when remembering is off.
func rememberIPWindow(p MFAPolicy) time.Duration {
	days := p.RememberIPDays
	switch {
	case days < 0:
		return 0
	case days == 0:
		days = DefaultRememberIPDays
	case days > MaxRememberIPDays:
		days = MaxRememberIPDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// Headers a reverse proxy usually adds. Their presence on a loopback
// connection while no forwarded header is configured means a proxy on
// the same host is hiding the real clients, who would then all share
// 127.0.0.1; nothing is remembered in that case.
var proxyHeaders = []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip"}

// mfaTrustKey is the address a passed check is remembered under, or ""
// when the request's address can't be relied on. The address comes from
// ClientIP: the TCP peer, or, only when GUI.forwarded_proxy_header is
// configured, the entry the proxy itself added. A forwarded header sent
// by the client is never trusted otherwise.
func mfaTrustKey(root *config_proto.Config, r *http.Request) string {
	ip := ClientIP(root, r)
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	if BehindSameHostProxy(root, ip) {
		for _, h := range proxyHeaders {
			if r.Header.Get(h) != "" {
				return ""
			}
		}
	}
	return normalizeIP(ip)
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// ipTrusted reports whether the user passed the second factor from this
// address within the window and nothing has revoked it since.
func ipTrusted(record *MFARecord, key string, window time.Duration, now time.Time) bool {
	if record == nil || key == "" || window <= 0 {
		return false
	}
	entry, ok := record.TrustedIPs[key]
	if !ok || entry.Generation != record.Generation {
		return false
	}
	passed := time.Unix(entry.Passed, 0)
	return !passed.After(now.Add(time.Minute)) && now.Sub(passed) < window
}

// rememberIP returns a record change that remembers the address and
// drops entries that are revoked, expired or over the limit. It runs
// after any other change in the same update, so it sees the final
// generation.
func rememberIP(key string, window time.Duration, now time.Time) func(r *MFARecord) error {
	return func(r *MFARecord) error {
		if r.TrustedIPs == nil {
			r.TrustedIPs = map[string]TrustedIP{}
		}
		if key != "" && window > 0 {
			r.TrustedIPs[key] = TrustedIP{Passed: now.Unix(), Generation: r.Generation}
		}
		pruneTrustedIPs(r, window, now)
		return nil
	}
}

func pruneTrustedIPs(r *MFARecord, window time.Duration, now time.Time) {
	for k, v := range r.TrustedIPs {
		if v.Generation != r.Generation || window <= 0 ||
			now.Sub(time.Unix(v.Passed, 0)) >= window {
			delete(r.TrustedIPs, k)
		}
	}
	if len(r.TrustedIPs) > maxTrustedIPs {
		keys := make([]string, 0, len(r.TrustedIPs))
		for k := range r.TrustedIPs {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return r.TrustedIPs[keys[i]].Passed > r.TrustedIPs[keys[j]].Passed
		})
		for _, k := range keys[maxTrustedIPs:] {
			delete(r.TrustedIPs, k)
		}
	}
	if len(r.TrustedIPs) == 0 {
		r.TrustedIPs = nil
	}
}

// mfaIPTrusted is the request-level check used by the gate.
func mfaIPTrusted(r *http.Request, root *config_proto.Config, record *MFARecord) bool {
	key := mfaTrustKey(root, r)
	if key == "" {
		return false
	}
	p, err := LoadMFAPolicy(root)
	if err != nil {
		return false
	}
	return ipTrusted(record, key, rememberIPWindow(p), time.Now())
}

// withRememberedIP chains the address change after apply, for the
// update that records a successful code.
func withRememberedIP(r *http.Request, root *config_proto.Config,
	apply func(rec *MFARecord) error) (func(rec *MFARecord) error, string) {
	key := mfaTrustKey(root, r)
	window := time.Duration(0)
	if p, err := LoadMFAPolicy(root); err == nil {
		window = rememberIPWindow(p)
	}
	remember := rememberIP(key, window, time.Now())
	if window <= 0 {
		key = ""
	}
	return func(rec *MFARecord) error {
		if apply != nil {
			if err := apply(rec); err != nil {
				return err
			}
		}
		return remember(rec)
	}, key
}
