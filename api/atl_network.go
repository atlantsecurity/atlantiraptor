package api

// GET/POST /api/v1/atl/network: the run-time network allowlists for the
// console and the integration API (see authenticators/network_allowlist.go).
// Server administrators of the root org only.

import (
	"encoding/json"
	"net/http"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/api/authenticators"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

type networkView struct {
	Policy        authenticators.NetworkPolicy `json:"policy"`
	YourIP        string                       `json:"your_ip"`
	YourIPIsLocal bool                         `json:"your_ip_is_local"`
	BreakGlass    bool                         `json:"break_glass_active"`
	StaticCIDRs   []string                     `json:"static_cidrs,omitempty"`
	// Requests arrive from loopback with no forwarded header configured:
	// probably a reverse proxy on this host, which makes every client
	// look local and the lists ineffective.
	ProxyWarning bool `json:"proxy_warning,omitempty"`
}

func networkHandler(config_obj *config_proto.Config) http.Handler {
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
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage network access."})
			return
		}

		ip := authenticators.ClientIP(config_obj, r)
		view := func(p authenticators.NetworkPolicy) networkView {
			v := networkView{Policy: p, BreakGlass: authenticators.AllowlistBreakGlass()}
			if ip != nil {
				v.YourIP, v.YourIPIsLocal = ip.String(), ip.IsLoopback()
			}
			v.ProxyWarning = authenticators.BehindSameHostProxy(config_obj, ip) && r.Header.Get("X-Forwarded-For") != ""
			if config_obj.GUI != nil {
				v.StaticCIDRs = config_obj.GUI.AllowedCidr
			}
			return v
		}

		switch r.Method {
		case http.MethodGet:
			p, err := authenticators.GetNetworkPolicy(root)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read the network policy."})
				return
			}
			groupsJSON(w, http.StatusOK, view(p))

		case http.MethodPost:
			var body struct {
				Policy         authenticators.NetworkPolicy `json:"policy"`
				ConfirmLockout bool                         `json:"confirm_lockout"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			p, err := authenticators.ValidateNetworkPolicy(body.Policy)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			// Saving a console list that leaves out the admin's own
			// address needs explicit confirmation.
			if p.Console.Enabled && (ip == nil || !ip.IsLoopback()) &&
				!authenticators.IPAllowedByEntries(ip, p.Console.Entries) && !body.ConfirmLockout {
				groupsJSON(w, http.StatusConflict, map[string]interface{}{
					"message": "This list doesn't include your address (" + ip.String() + "). You would lose access to the console from here.",
					"code":    "would_lock_out",
				})
				return
			}
			if p.API.Enabled && len(p.API.Entries) == 0 && !body.ConfirmLockout {
				groupsJSON(w, http.StatusConflict, map[string]interface{}{
					"message": "The API list is empty: only this server itself could use the integration API.",
					"code":    "would_lock_out",
				})
				return
			}
			if p.Console.Enabled && len(p.Console.Entries) == 0 && !body.ConfirmLockout {
				groupsJSON(w, http.StatusConflict, map[string]interface{}{
					"message": "The console list is empty: only this server itself could reach the console.",
					"code":    "would_lock_out",
				})
				return
			}
			saved, err := authenticators.SaveNetworkPolicy(root, p, principal)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not save the network policy."})
				return
			}
			if err := services.LogAudit(r.Context(), root, principal, "network_policy_update",
				ordereddict.NewDict().Set("policy", saved).Set("from", ip.String())); err != nil {
				logging.GetLogger(root, &logging.FrontendComponent).Error("network_policy_update %v", principal)
			}
			groupsJSON(w, http.StatusOK, view(saved))

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
