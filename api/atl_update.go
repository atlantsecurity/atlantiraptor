package api

// GET/POST /api/v1/atl/update: the server's self-update from GitHub
// releases (see services/selfupdate). Server administrators of the
// root org only.
//
// GET returns the status. POST takes {"action": ...}:
//   check     ask GitHub for the latest release now
//   install   download, verify and switch to the latest release
//   settings  {"auto_install": bool, "check_hours": int}

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
	"www.velocidex.com/golang/velociraptor/utils"
)

func updateHandler(config_obj *config_proto.Config) http.Handler {
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
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage server updates."})
			return
		}

		updater := selfupdate.Get()

		switch r.Method {
		case http.MethodGet:
			groupsJSON(w, http.StatusOK, updater.Status())

		case http.MethodPost:
			var body struct {
				Action      string `json:"action"`
				AutoInstall bool   `json:"auto_install"`
				CheckHours  int    `json:"check_hours"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			audit := func(op string, details *ordereddict.Dict) {
				if err := services.LogAudit(r.Context(), root, principal, op, details); err != nil {
					logging.GetLogger(root, &logging.FrontendComponent).Error("%v %v", op, principal)
				}
			}

			switch body.Action {
			case "check":
				ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
				defer cancel()
				status, err := updater.Check(ctx)
				if err != nil {
					status.LastError = err.Error()
				}
				groupsJSON(w, http.StatusOK, status)

			case "install":
				audit("server_self_update_requested", ordereddict.NewDict().
					Set("latest", updater.Status().LatestVersion))
				// The download can take minutes; it must not stop when
				// the browser gives up waiting.
				err := updater.Install(context.Background(), principal)
				if err != nil {
					groupsJSON(w, http.StatusConflict, map[string]string{"message": err.Error()})
					return
				}
				groupsJSON(w, http.StatusAccepted, updater.Status())

			case "settings":
				saved, err := updater.SetSettings(body.AutoInstall, body.CheckHours, principal)
				if err != nil {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
					return
				}
				audit("server_self_update_settings", ordereddict.NewDict().
					Set("auto_install", saved.AutoInstall).Set("check_hours", saved.CheckHours))
				groupsJSON(w, http.StatusOK, updater.Status())

			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
			}

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
