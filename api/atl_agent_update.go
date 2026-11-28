package api

// GET/POST /api/v1/atl/agent-update: automatic agent upgrades after a
// server update (see services/agentupdate). Server administrators of
// the root org only.
//
// GET returns the status. POST takes {"action": ...}:
//   settings      {"settings": {"enabled", "pinned_version",
//                  "canary_percent", "canary_hours", "exclude_label"}}
//   resume        move a paused or canary rollout to every agent
//   retry_failed  give agents whose upgrade failed new attempts
//   run           run a round now

import (
	"encoding/json"
	"net/http"

	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/agentupdate"
	"www.velocidex.com/golang/velociraptor/utils"
)

func agentUpdateHandler(config_obj *config_proto.Config) http.Handler {
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
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage agent updates."})
			return
		}

		service := agentupdate.Get()

		switch r.Method {
		case http.MethodGet:
			groupsJSON(w, http.StatusOK, service.Status())

		case http.MethodPost:
			var body struct {
				Action   string               `json:"action"`
				Settings agentupdate.Settings `json:"settings"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			var status agentupdate.Status
			switch body.Action {
			case "settings":
				status, err = service.SetSettings(r.Context(), body.Settings, principal)
			case "resume":
				status, err = service.Resume(r.Context(), principal)
			case "retry_failed":
				status, err = service.RetryFailed(r.Context(), principal)
			case "run":
				service.RunNow()
				status = service.Status()
			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
				return
			}
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			groupsJSON(w, http.StatusOK, status)

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
