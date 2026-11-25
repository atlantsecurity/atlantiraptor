package api

// /api/v1/atl/apikeys: console endpoint for server administrators to
// list, create and revoke SIEM/SOAR API keys. It sits behind the normal
// console authentication, CSRF protection and 2FA.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const maxKeyTTLDays = 3650

func apiKeysHandler() http.Handler {
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
		org_config, err := org_manager.GetOrgConfig(r.Header.Get("Grpc-Metadata-OrgId"))
		if err != nil {
			groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown org."})
			return
		}
		ok, err := services.CheckAccess(org_config, principal, acls.SERVER_ADMIN)
		if err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage API keys."})
			return
		}
		audit := func(op string, d *ordereddict.Dict) {
			if err := services.LogAudit(r.Context(), org_config, principal, op, d); err != nil {
				logging.GetLogger(org_config, &logging.FrontendComponent).Error("%v %v", op, principal)
			}
		}

		switch r.Method {
		case http.MethodGet:
			keys, err := ListAPIKeys(root)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read API keys."})
				return
			}
			// Only this org's keys.
			out := []APIKey{}
			for _, k := range keys {
				if k.OrgId == org_config.OrgId || (utils.IsRootOrg(k.OrgId) && utils.IsRootOrg(org_config.OrgId)) {
					out = append(out, k)
				}
			}
			groupsJSON(w, http.StatusOK, map[string]interface{}{"keys": out, "roles": apiKeyRoles})

		case http.MethodPost:
			var body struct {
				Name    string   `json:"name"`
				Roles   []string `json:"roles"`
				TTLDays int      `json:"ttl_days"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			if body.TTLDays < 0 || body.TTLDays > maxKeyTTLDays {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "ttl_days must be 0 (no expiry) to 3650"})
				return
			}
			key, token, err := CreateAPIKey(root, org_config, principal, strings.TrimSpace(body.Name),
				body.Roles, time.Duration(body.TTLDays)*24*time.Hour)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			audit("api_key_create", ordereddict.NewDict().Set("key_id", key.ID).Set("name", key.Name).
				Set("roles", key.Roles).Set("expires", key.Expires))
			groupsJSON(w, http.StatusOK, map[string]interface{}{"key": key, "token": token})

		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			keys, err := ListAPIKeys(root)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read API keys."})
				return
			}
			allowed := false
			for _, k := range keys {
				if k.ID == id && (k.OrgId == org_config.OrgId ||
					(utils.IsRootOrg(k.OrgId) && utils.IsRootOrg(org_config.OrgId))) {
					allowed = true
				}
			}
			if !allowed {
				groupsJSON(w, http.StatusNotFound, map[string]string{"message": "No such key in this org."})
				return
			}
			key, err := RevokeAPIKey(root, id)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			audit("api_key_revoke", ordereddict.NewDict().Set("key_id", key.ID).Set("name", key.Name))
			groupsJSON(w, http.StatusOK, map[string]interface{}{"revoked": key})

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET, POST or DELETE"})
		}
	})
}
