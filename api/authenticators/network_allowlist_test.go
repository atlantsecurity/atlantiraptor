package authenticators

import (
	"net"
	"net/http/httptest"
	"testing"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestParseNetworkEntry(t *testing.T) {
	for _, ok := range []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "2001:db8::1", " 172.16.0.1 "} {
		if _, err := ParseNetworkEntry(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/33", "not-an-ip", "10.0.0", "1.2.3.4/abc"} {
		if _, err := ParseNetworkEntry(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIPAllowedByEntries(t *testing.T) {
	if !IPAllowedByEntries(net.ParseIP("203.0.113.5"), nil) {
		t.Error("empty list must allow")
	}
	entries := []string{"10.0.0.0/8", "192.0.2.7"}
	if !IPAllowedByEntries(net.ParseIP("10.1.2.3"), entries) || !IPAllowedByEntries(net.ParseIP("192.0.2.7"), entries) {
		t.Error("listed addresses refused")
	}
	if IPAllowedByEntries(net.ParseIP("192.0.2.8"), entries) || IPAllowedByEntries(nil, entries) {
		t.Error("unlisted address allowed")
	}
}

func TestClientIPUsesOnlyLastForwardedEntry(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.1:5555"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9")
	if got := ClientIP(&config_proto.Config{}, r).String(); got != "198.51.100.1" {
		t.Errorf("without a configured proxy header the socket address must be used, got %v", got)
	}
	cfg := &config_proto.Config{GUI: &config_proto.GUIConfig{ForwardedProxyHeader: "X-Forwarded-For"}}
	if got := ClientIP(cfg, r).String(); got != "203.0.113.9" {
		t.Errorf("expected the proxy-added (last) entry, got %v", got)
	}
	r.RemoteAddr = "[2001:db8::5]:443"
	if got := ClientIP(&config_proto.Config{}, r).String(); got != "2001:db8::5" {
		t.Errorf("IPv6 remote address, got %v", got)
	}
}

func TestValidateNetworkPolicy(t *testing.T) {
	p, err := ValidateNetworkPolicy(NetworkPolicy{Console: NetworkList{Enabled: true, Entries: []string{" 10.0.0.0/8 ", ""}}})
	if err != nil || len(p.Console.Entries) != 1 || p.Console.Entries[0] != "10.0.0.0/8" {
		t.Fatalf("got %+v %v", p, err)
	}
	if _, err := ValidateNetworkPolicy(NetworkPolicy{API: NetworkList{Entries: []string{"bogus"}}}); err == nil {
		t.Error("bad entry accepted")
	}
}

func TestClientIPForwardedHeaderEdgeCases(t *testing.T) {
	cfg := &config_proto.Config{GUI: &config_proto.GUIConfig{ForwardedProxyHeader: "X-Forwarded-For"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	// Configured but missing: no address (refused by enabled lists).
	if ip := ClientIP(cfg, r); ip != nil {
		t.Errorf("missing header must give no address, got %v", ip)
	}
	// Two header lines: the proxy's (last) line wins.
	r.Header.Add("X-Forwarded-For", "10.0.0.5")
	r.Header.Add("X-Forwarded-For", "203.0.113.9:4444")
	if got := ClientIP(cfg, r); got == nil || got.String() != "203.0.113.9" {
		t.Errorf("expected the proxy-added entry with its port stripped, got %v", got)
	}
	// Garbage: no address rather than falling back to the (loopback) socket.
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if ip := ClientIP(cfg, r); ip != nil {
		t.Errorf("garbage header must give no address, got %v", ip)
	}
}

func TestDeniedKeyGroupsIPv6(t *testing.T) {
	a := deniedKey("console", net.ParseIP("2001:db8::1"))
	b := deniedKey("console", net.ParseIP("2001:db8::ffff"))
	if a != b {
		t.Errorf("addresses in one /64 should share a key: %v %v", a, b)
	}
}
