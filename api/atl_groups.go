package api

// GET/POST /api/v1/atl/groups: list or replace the current org's user
// groups. Server administrators of the org only. Group roles are
// enforced by the ACL manager (see services/acl_manager/groups.go).

import (
	"encoding/json"
	"net/http"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/acl_manager"
	"www.velocidex.com/golang/velociraptor/utils"
)

func groupsJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func groupsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}

		org_id := r.Header.Get("Grpc-Metadata-OrgId")
		org_manager, err := services.GetOrgManager()
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		var org_config_obj *config_proto.Config
		org_config_obj, err = org_manager.GetOrgConfig(org_id)
		if err != nil {
			groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown org."})
			return
		}

		ok, err := services.CheckAccess(org_config_obj, principal, acls.SERVER_ADMIN)
		if err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage groups."})
			return
		}

		switch r.Method {
		case http.MethodGet:
			groups, err := acl_manager.GetGroups(org_config_obj)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read groups."})
				return
			}
			if groups == nil {
				groups = []acl_manager.Group{}
			}
			groupsJSON(w, http.StatusOK, map[string]interface{}{"groups": groups})

		case http.MethodPost:
			var body struct {
				Groups []acl_manager.Group `json:"groups"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			saved, err := acl_manager.SetGroups(org_config_obj, body.Groups)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			if err := services.LogAudit(r.Context(), org_config_obj, principal, "groups_update",
				ordereddict.NewDict().Set("groups", saved)); err != nil {
				logging.GetLogger(org_config_obj, &logging.FrontendComponent).
					Error("groups_update %v", principal)
			}
			groupsJSON(w, http.StatusOK, map[string]interface{}{"groups": saved})

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}
