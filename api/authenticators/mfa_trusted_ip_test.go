package authenticators

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestRememberIPWindow(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		days int
		want time.Duration
	}{{0, 30 * day}, {-1, 0}, {-5, 0}, {7, 7 * day}, {1000, MaxRememberIPDays * day}} {
		if got := rememberIPWindow(MFAPolicy{Mode: MFAModeAll, RememberIPDays: c.days}); got != c.want {
			t.Errorf("days=%d: got %v want %v", c.days, got, c.want)
		}
	}
}

func TestTrustedIP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	window := 30 * 24 * time.Hour
	rec := &MFARecord{TOTPSecret: "x", Generation: 2}
	if err := rememberIP("10.0.0.5", window, now)(rec); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		key    string
		at     time.Time
		window time.Duration
		ok     bool
	}{
		{"same ip", "10.0.0.5", now.Add(time.Hour), window, true},
		{"other ip", "10.0.0.6", now.Add(time.Hour), window, false},
		{"expired", "10.0.0.5", now.Add(window), window, false},
		{"policy shortened", "10.0.0.5", now.Add(2 * 24 * time.Hour), 24 * time.Hour, false},
		{"remembering off", "10.0.0.5", now, 0, false},
		{"empty key", "", now, window, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ipTrusted(rec, c.key, c.window, c.at); got != c.ok {
				t.Errorf("got %v want %v", got, c.ok)
			}
		})
	}

	// A revocation (password change, reset) forgets every address.
	rec.Generation++
	if ipTrusted(rec, "10.0.0.5", window, now) {
		t.Error("address still trusted after the generation changed")
	}
	_ = rememberIP("", window, now)(rec)
	if len(rec.TrustedIPs) != 0 {
		t.Errorf("revoked entries were not pruned: %v", rec.TrustedIPs)
	}

	// Enrolment bumps the generation in the same update; the address
	// must be stored under the new generation.
	rec2 := &MFARecord{}
	_ = rememberIP("10.0.0.7", window, now)(rec2)
	rec2.Generation++
	if ipTrusted(rec2, "10.0.0.7", window, now) {
		t.Error("ordering: remembered before the generation bump should not count")
	}
}

func TestTrustedIPLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	window := 30 * 24 * time.Hour
	rec := &MFARecord{TOTPSecret: "x"}
	for i := 0; i < maxTrustedIPs+10; i++ {
		_ = rememberIP(fmt.Sprintf("10.0.1.%d", i), window, now.Add(time.Duration(i)*time.Second))(rec)
	}
	if len(rec.TrustedIPs) != maxTrustedIPs {
		t.Fatalf("kept %d entries, want %d", len(rec.TrustedIPs), maxTrustedIPs)
	}
	if _, ok := rec.TrustedIPs["10.0.1.0"]; ok {
		t.Error("oldest entry was kept")
	}
	if _, ok := rec.TrustedIPs[fmt.Sprintf("10.0.1.%d", maxTrustedIPs+9)]; !ok {
		t.Error("newest entry was dropped")
	}
}

func TestMFATrustKey(t *testing.T) {
	direct := &config_proto.Config{GUI: &config_proto.GUIConfig{}}
	proxied := &config_proto.Config{GUI: &config_proto.GUIConfig{ForwardedProxyHeader: "X-Forwarded-For"}}

	cases := []struct {
		name    string
		cfg     *config_proto.Config
		remote  string
		headers map[string]string
		want    string
	}{
		{"direct client", direct, "203.0.113.9:5555", nil, "203.0.113.9"},
		{"spoofed header ignored without proxy config", direct, "203.0.113.9:5555",
			map[string]string{"X-Forwarded-For": "198.51.100.1"}, "203.0.113.9"},
		{"local browser", direct, "127.0.0.1:5555", nil, "127.0.0.1"},
		{"unconfigured same-host proxy is not trusted", direct, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "198.51.100.1"}, ""},
		{"configured proxy uses the entry it added", proxied, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "198.51.100.66, 198.51.100.1"}, "198.51.100.1"},
		{"configured proxy, header missing", proxied, "127.0.0.1:5555", nil, ""},
		{"ipv6", direct, "[2001:db8::1]:443", nil, "2001:db8::1"},
		{"ipv4-mapped ipv6", direct, "[::ffff:203.0.113.9]:443", nil, "203.0.113.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := mfaTrustKey(c.cfg, r); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestPolicyRememberValidation(t *testing.T) {
	p := MFAPolicy{Mode: MFAModeAll, RememberIPDays: MaxRememberIPDays + 1}
	if validateMFAPolicy(&p) == nil {
		t.Error("too many days accepted")
	}
	p = MFAPolicy{Mode: MFAModeAll, RememberIPDays: -7}
	if err := validateMFAPolicy(&p); err != nil || p.RememberIPDays != -1 {
		t.Errorf("negative not normalised: %v %v", p.RememberIPDays, err)
	}
}
