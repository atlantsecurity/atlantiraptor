package api

// GET/POST /api/v1/atl/feeds: Atlant Security's premium hunt feeds
// (see services/huntfeeds).
//
// GET returns the subscription state and the available hunt packs to
// any console user who can read results, plus can_manage when they are
// a server administrator. POST is for server administrators of the
// root org and takes {"action": ...}:
//   sync        fetch the feed now
//   set_key     {"key": "..."} save a licence key and fetch the feed
//   remove_key  forget the licence key and remove the feed packs

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/huntfeeds"
	"www.velocidex.com/golang/velociraptor/utils"
)

type feedsResponse struct {
	huntfeeds.Status
	CanManage bool `json:"can_manage"`
}

func feedsHandler(config_obj *config_proto.Config) http.Handler {
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
		is_admin, _ := services.CheckAccess(root, principal, acls.SERVER_ADMIN)
		feeds := huntfeeds.Get()
		reply := func(code int) {
			groupsJSON(w, code, feedsResponse{Status: feeds.Status(), CanManage: is_admin})
		}

		switch r.Method {
		case http.MethodGet:
			reply(http.StatusOK)

		case http.MethodPost:
			if !is_admin {
				groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage the hunt feed subscription."})
				return
			}
			var body struct {
				Action string `json:"action"`
				Key    string `json:"key"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}

			switch body.Action {
			case "sync":
				ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
				defer cancel()
				// The outcome is in the status (state, message, last_error).
				_ = feeds.Sync(ctx)
				reply(http.StatusOK)

			case "set_key", "remove_key":
				key := body.Key
				if body.Action == "remove_key" {
					key = ""
				} else if key == "" {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Enter a licence key."})
					return
				}
				if err := feeds.SetLicenceKey(key, principal); err != nil {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
					return
				}
				if key != "" {
					// Answer with the result of the first sync when it is quick.
					ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
					defer cancel()
					_ = feeds.Sync(ctx)
				}
				reply(http.StatusOK)

			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
			}

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
