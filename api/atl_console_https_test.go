package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"www.velocidex.com/golang/velociraptor/api/authenticators"
	"www.velocidex.com/golang/velociraptor/config"
)

// A browser on the extra listener must not be able to pick its own
// address through the forwarded header meant for a reverse proxy.
func TestDirectHandlerReplacesForwardedHeader(t *testing.T) {
	config_obj := config.GetDefaultConfig()
	config_obj.GUI.ForwardedProxyHeader = "X-Forwarded-For"
	var seen string
	h := directHandler(config_obj, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authenticators.ClientIP(config_obj, r).String()
	}))
	req := httptest.NewRequest("GET", "/app/index.html", nil)
	req.RemoteAddr = "203.0.113.9:51515"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "203.0.113.9" {
		t.Fatalf("client address %q", seen)
	}
}

func TestConsoleHTTPSOptions(t *testing.T) {
	config_obj := config.GetDefaultConfig()
	config_obj.GUI.BindAddress = "127.0.0.1"
	config_obj.GUI.BindPort = 8889
	config_obj.Frontend.BindPort = 8000
	config_obj.Frontend.Hostname = "server.example.com"
	opts := consoleHTTPSOptions(config_obj, http.NotFoundHandler())
	if opts.Unavailable != "" || opts.ApplyWarning == "" {
		t.Fatalf("%+v", opts)
	}
	if opts.RecoveryURL != "https://server.example.com:8889/app/index.html" && config_obj.GUI.PublicUrl == "" {
		t.Errorf("recovery %q", opts.RecoveryURL)
	}
	config_obj.AutocertCertCache = "/tmp/x"
	if consoleHTTPSOptions(config_obj, nil).Unavailable == "" {
		t.Error("autocert config should make it unavailable")
	}
}
