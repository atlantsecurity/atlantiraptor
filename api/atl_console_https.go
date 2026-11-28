package api

// GET/POST /api/v1/atl/https: serve the console on a host name with a
// browser-trusted certificate (see api/consolehttps). Server
// administrators of the root org only; every change is audited.
//
// GET returns the state. POST takes {"action": ...}:
//   apply    {"settings": {...}, "upload": {...}, "keep_certificate": bool, "confirm": bool}
//   confirm  keep the settings on trial
//   revert   undo the settings on trial now
//   disable  stop serving the extra address
//   dns      {"hostname": "..."}: where the name points

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/api/authenticators"
	"www.velocidex.com/golang/velociraptor/api/consolehttps"
	api_utils "www.velocidex.com/golang/velociraptor/api/utils"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

type consoleHTTPSView struct {
	consolehttps.View
	DNS      []string `json:"dns,omitempty"`
	DNSError string   `json:"dns_error,omitempty"`
}

func lookupHost(hostname string) ([]string, string) {
	if hostname == "" {
		return nil, ""
	}
	if net.ParseIP(hostname) != nil {
		return []string{hostname}, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, fmt.Sprintf("%s does not resolve from this server yet. Create a DNS record pointing it at this server's address.", hostname)
	}
	return addrs, ""
}

func consoleHTTPSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}
		org_manager, err := services.GetOrgManager()
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		root, err := org_manager.GetOrgConfig(services.ROOT_ORG_ID)
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		if ok, err := services.CheckAccess(root, principal, acls.SERVER_ADMIN); err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can change the console's address and certificate."})
			return
		}

		m := consolehttps.Get()
		withDNS := func(v consolehttps.View) consoleHTTPSView {
			out := consoleHTTPSView{View: v}
			host := v.Active.Hostname
			if v.Pending != nil {
				host = v.Pending.Settings.Hostname
			}
			out.DNS, out.DNSError = lookupHost(host)
			return out
		}

		switch r.Method {
		case http.MethodGet:
			groupsJSON(w, http.StatusOK, withDNS(m.Status()))

		case http.MethodPost:
			var body struct {
				Action          string                `json:"action"`
				Settings        consolehttps.Settings `json:"settings"`
				Upload          consolehttps.Upload   `json:"upload"`
				KeepCertificate bool                  `json:"keep_certificate"`
				Confirm         bool                  `json:"confirm"`
				Hostname        string                `json:"hostname"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			var view consolehttps.View
			var warnings []string
			switch body.Action {
			case "apply":
				view, warnings, err = m.Apply(r.Context(), principal, body.Settings, body.Upload,
					body.KeepCertificate, body.Confirm)
			case "confirm":
				view, err = m.Confirm(r.Context(), principal)
			case "revert":
				view, err = m.Revert(r.Context(), principal)
			case "disable":
				view, err = m.Disable(r.Context(), principal)
			case "dns":
				host, herr := consolehttps.NormalizeHostname(body.Hostname, true)
				if herr != nil {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": herr.Error()})
					return
				}
				addrs, msg := lookupHost(host)
				groupsJSON(w, http.StatusOK, map[string]interface{}{"hostname": host, "dns": addrs, "dns_error": msg})
				return
			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
				return
			}
			if err != nil {
				status := http.StatusBadRequest
				code := ""
				var ae *consolehttps.ApplyError
				if errors.As(err, &ae) {
					code = ae.Code
					switch ae.Code {
					case "needs_confirmation":
						status = http.StatusConflict
					case "listen_failed":
						status = http.StatusUnprocessableEntity
					case "save_failed":
						status = http.StatusInternalServerError
					case "unavailable":
						status = http.StatusServiceUnavailable
					}
				}
				groupsJSON(w, status, map[string]interface{}{
					"message": err.Error(), "code": code, "warnings": warnings, "state": withDNS(view),
				})
				return
			}
			out := withDNS(view)
			groupsJSON(w, http.StatusOK, map[string]interface{}{"state": out, "warnings": warnings})

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}

var consoleHTTPSOnce sync.Once

// startConsoleHTTPS starts the extra console listener next to the main
// console. Called once, with the console's handler, wherever the GUI is
// started.
func startConsoleHTTPS(ctx context.Context, wg *sync.WaitGroup,
	config_obj *config_proto.Config, router http.Handler) {
	consoleHTTPSOnce.Do(func() {
		consolehttps.Get().Start(ctx, wg, config_obj, consoleHTTPSOptions(config_obj, router))
	})
}

func consoleHTTPSOptions(config_obj *config_proto.Config, router http.Handler) consolehttps.Options {
	opts := consolehttps.Options{
		Handler: directHandler(config_obj, router),
		AppPath: api_utils.GetBasePath(config_obj, "/app/index.html"),
	}
	gui, fe := config_obj.GUI, config_obj.Frontend
	if gui == nil || fe == nil {
		opts.Unavailable = "This server doesn't run the console."
		return opts
	}
	opts.PublicURL = gui.PublicUrl
	if gui.Authenticator != nil {
		opts.Authenticator = strings.ToLower(gui.Authenticator.Type)
	}

	scheme := "https"
	if gui.UsePlainHttp {
		scheme = "http"
	}
	host := fe.Hostname
	if host == "" {
		host = "localhost"
	}
	opts.RecoveryURL = fmt.Sprintf("%s://%s:%d%s", scheme, host, gui.BindPort, opts.AppPath)
	if gui.PublicUrl != "" {
		opts.RecoveryURL = gui.PublicUrl
	}

	opts.Reserved = []consolehttps.ReservedPort{
		{Port: gui.BindPort, Use: "the console's main address"},
		{Port: fe.BindPort, Use: "client connections"},
	}
	if config_obj.API != nil {
		opts.Reserved = append(opts.Reserved, consolehttps.ReservedPort{Port: config_obj.API.BindPort, Use: "the gRPC API"})
	}
	if config_obj.Monitoring != nil {
		opts.Reserved = append(opts.Reserved, consolehttps.ReservedPort{Port: config_obj.Monitoring.BindPort, Use: "the metrics endpoint"})
	}

	if ip := net.ParseIP(gui.BindAddress); ip != nil && ip.IsLoopback() {
		opts.ApplyWarning = "The console's main address only listens on this server itself (GUI.bind_address is " +
			gui.BindAddress + "), probably behind a reverse proxy. The new address is reachable from the network directly, " +
			"without the proxy and anything it adds, such as single sign-on. Network access lists still apply."
	}

	switch {
	case fe.IsMinion:
		opts.Unavailable = "This is a minion node. Set up HTTPS on the master node."
	case config_obj.AutocertCertCache != "":
		opts.Unavailable = "This server already uses Let's Encrypt from its config file (autocert_domain), on ports 443 and 80."
	}

	if auther, err := authenticators.NewAuthenticator(config_obj); err == nil && auther.RequireClientCerts() {
		opts.ExtraTLS = func(t *tls.Config) error { return addClientCerts(config_obj, t) }
	}
	return opts
}

// directHandler serves the console to browsers that connect straight to
// the extra listener, never through the reverse proxy the config file
// may describe. When GUI.forwarded_proxy_header is set, the client could
// otherwise send that header itself and pose as any address (even
// localhost) to the network access lists, so it is replaced with the
// real peer address.
func directHandler(config_obj *config_proto.Config, h http.Handler) http.Handler {
	if config_obj.GUI == nil || config_obj.GUI.ForwardedProxyHeader == "" {
		return h
	}
	hdr := config_obj.GUI.ForwardedProxyHeader
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		r.Header.Del(hdr)
		r.Header.Set(hdr, host)
		h.ServeHTTP(w, r)
	})
}
