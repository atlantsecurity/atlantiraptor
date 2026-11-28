package api

// GET /api/v1/atl/fleet: fleet health for the current org (counts,
// quiet agents and an agent version histogram), computed here so the
// console does not download every client record.
//
// GET /api/v1/atl/fleet?os=windows&versions=1.0.4,1.0.5 instead returns
// the IDs of the clients of that OS running those versions, for the
// agent upgrade dialog.
//
// Anyone who may read results in the org may call it.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"www.velocidex.com/golang/velociraptor/acls"
	actions_proto "www.velocidex.com/golang/velociraptor/actions/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

// Each quiet list shows at most this many hosts; the counts are exact.
const fleetMaxListed = 200

func fleetJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func listFleetClients(ctx context.Context, config_obj *config_proto.Config) ([]fleetClient, error) {
	client_info_manager, err := services.GetClientInfoManager(config_obj)
	if err != nil {
		return nil, err
	}

	res := []fleetClient{}
	for client_id := range client_info_manager.ListClients(ctx) {
		if client_id == "" || client_id == "server" {
			continue
		}
		item, err := services.GetClientInfoItem(ctx, config_obj, client_id,
			func(record *actions_proto.ClientInfo) (interface{}, error) {
				return fleetClient{
					ClientId:   client_id,
					Hostname:   record.Hostname,
					OS:         record.System,
					Version:    record.ClientVersion,
					LastSeenAt: record.Ping,
				}, nil
			})
		if err != nil {
			continue
		}
		if c, ok := item.(fleetClient); ok {
			res = append(res, c)
		}
	}
	return res, nil
}

func fleetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fleetJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET only"})
			return
		}

		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}

		org_manager, err := services.GetOrgManager()
		if err != nil {
			fleetJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		org_config_obj, err := org_manager.GetOrgConfig(r.Header.Get("Grpc-Metadata-OrgId"))
		if err != nil {
			fleetJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown org."})
			return
		}

		ok, err := services.CheckAccess(org_config_obj, principal, acls.READ_RESULTS)
		if err != nil || !ok {
			fleetJSON(w, http.StatusForbidden, map[string]string{"message": "You are not allowed to view clients."})
			return
		}

		clients, err := listFleetClients(r.Context(), org_config_obj)
		if err != nil {
			logging.GetLogger(org_config_obj, &logging.FrontendComponent).
				Error("fleet: listing clients: %v", err)
			fleetJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not list clients."})
			return
		}

		q := r.URL.Query()
		if os := q.Get("os"); os != "" {
			versions := []string{}
			for _, v := range strings.Split(q.Get("versions"), ",") {
				if v = strings.TrimSpace(v); v != "" {
					versions = append(versions, v)
				}
			}
			fleetJSON(w, http.StatusOK, map[string]interface{}{
				"client_ids": filterFleetClients(clients, os, versions),
			})
			return
		}

		fleetJSON(w, http.StatusOK, summarizeFleet(clients, time.Now(), fleetMaxListed))
	})
}
