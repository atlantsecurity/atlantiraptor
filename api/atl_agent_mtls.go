package api

// GET/POST /api/v1/atl/agent-mtls: agent certificates on the agent
// port (see services/agentmtls), console page Server settings > Agent
// connections, and blocking single agents. Server administrators of
// the root org only.
//
// GET returns the status. POST takes {"action": ...}:
//   settings  {"settings": {"mode", "allow_enrollment", "allow_legacy"},
//              "force": bool}  (force: turn on Enforce even though
//              agents seen recently would be refused)
//   rotate    issue a new deployment certificate
//   block     {"client_id", "org_id", "reason"}
//   unblock   {"client_id"}

import (
	"encoding/json"
	"errors"
	"net/http"

	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/agentmtls"
	"www.velocidex.com/golang/velociraptor/utils"
)

func agentMTLSHandler(config_obj *config_proto.Config) http.Handler {
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
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage agent connections."})
			return
		}

		service := agentmtls.Get()

		switch r.Method {
		case http.MethodGet:
			groupsJSON(w, http.StatusOK, service.Status(r.Context()))

		case http.MethodPost:
			var body struct {
				Action   string             `json:"action"`
				Settings agentmtls.Settings `json:"settings"`
				Force    bool               `json:"force"`
				ClientId string             `json:"client_id"`
				OrgId    string             `json:"org_id"`
				Reason   string             `json:"reason"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			var status agentmtls.Status
			switch body.Action {
			case "settings":
				status, err = service.SetSettings(r.Context(), body.Settings, principal, body.Force)
			case "rotate":
				status, err = service.RotateDeployment(r.Context(), principal)
			case "block":
				hostname := ""
				if org_config, err := org_manager.GetOrgConfig(body.OrgId); err == nil {
					if cim, err := services.GetClientInfoManager(org_config); err == nil {
						if info, err := cim.Get(r.Context(), body.ClientId); err == nil && info != nil {
							hostname = info.Hostname
						}
					}
				}
				status, err = service.Block(r.Context(), body.ClientId, body.OrgId,
					hostname, body.Reason, principal)
			case "unblock":
				status, err = service.Unblock(r.Context(), body.ClientId, principal)
			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
				return
			}
			if err != nil {
				var not_ready agentmtls.ErrNotReady
				if errors.As(err, &not_ready) {
					groupsJSON(w, http.StatusConflict, map[string]interface{}{
						"message": err.Error(), "would_refuse": not_ready.Count})
					return
				}
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			groupsJSON(w, http.StatusOK, status)

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
