package api

// /api/v1/atl/orgs: organization management for the console.
//
//   GET                         list orgs with their member counts
//   GET ?client_config=<org_id> download an org's client config (YAML)
//   POST {"action":"create","name":...}
//   POST {"action":"rename","id":...,"name":...}
//   POST {"action":"delete","id":...,"confirm":<org name>}
//
// Every call needs ORG_ADMIN in the root org (the administrator role in
// the root org, or the org_admin role), whatever org the console is
// currently showing. Changes are written to the audit log.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/yaml/v2"
	"www.velocidex.com/golang/velociraptor/acls"
	acl_proto "www.velocidex.com/golang/velociraptor/acls/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/orgs"
	"www.velocidex.com/golang/velociraptor/utils"
)

type atlOrg struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Root       bool   `json:"root,omitempty"`
	Redirected bool   `json:"redirected,omitempty"`
	Users      int    `json:"users"`
}

var orgIdRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func orgsJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func orgsError(w http.ResponseWriter, status int, msg string) {
	orgsJSON(w, status, map[string]string{"message": msg})
}

func orgsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}

		org_manager, err := services.GetOrgManager()
		if err != nil {
			orgsError(w, http.StatusInternalServerError, "Server not ready.")
			return
		}
		root_config_obj, err := org_manager.GetOrgConfig(services.ROOT_ORG_ID)
		if err != nil {
			orgsError(w, http.StatusInternalServerError, "Server not ready.")
			return
		}
		ok, err := services.CheckAccess(root_config_obj, principal, acls.ORG_ADMIN)
		if err != nil || !ok {
			orgsError(w, http.StatusForbidden,
				"Only organization administrators (administrators of the root org) can manage organizations.")
			return
		}

		switch r.Method {
		case http.MethodGet:
			if id := r.URL.Query().Get("client_config"); id != "" {
				orgClientConfig(w, org_manager, id)
				return
			}
			orgsList(w, r, org_manager, principal)

		case http.MethodPost:
			var body struct {
				Action  string `json:"action"`
				Id      string `json:"id"`
				Name    string `json:"name"`
				Confirm string `json:"confirm"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
				orgsError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			switch body.Action {
			case "create":
				orgCreate(w, r, root_config_obj, org_manager, principal, body.Name)
			case "rename":
				orgRename(w, r, root_config_obj, org_manager, principal, body.Id, body.Name)
			case "delete":
				orgDelete(w, r, root_config_obj, org_manager, principal, body.Id, body.Confirm)
			default:
				orgsError(w, http.StatusBadRequest, "Unknown action.")
			}

		default:
			orgsError(w, http.StatusMethodNotAllowed, "GET or POST")
		}
	})
}

func orgsList(w http.ResponseWriter, r *http.Request,
	org_manager services.OrgManager, principal string) {

	counts := map[string]int{}
	users, err := services.GetUserManager().ListUsers(r.Context(), principal, services.LIST_ALL_ORGS)
	if err == nil {
		for _, u := range users {
			for _, o := range u.Orgs {
				counts[utils.NormalizedOrgId(o.Id)]++
			}
		}
	}

	result := []atlOrg{}
	for _, o := range org_manager.ListOrgs() {
		id := utils.NormalizedOrgId(o.Id)
		root := utils.IsRootOrg(id)
		if root {
			id = services.ROOT_ORG_ID
		}
		result = append(result, atlOrg{
			Id:         id,
			Name:       o.Name,
			Root:       root,
			Redirected: o.Redirected,
			Users:      counts[utils.NormalizedOrgId(o.Id)],
		})
	}
	orgsJSON(w, http.StatusOK, map[string]interface{}{"orgs": result})
}

func orgClientConfig(w http.ResponseWriter, org_manager services.OrgManager, id string) {
	if !orgIdRegex.MatchString(id) {
		orgsError(w, http.StatusBadRequest, "Bad org id.")
		return
	}
	org_config_obj, err := org_manager.GetOrgConfig(id)
	if err != nil || org_config_obj.Client == nil {
		orgsError(w, http.StatusNotFound, "Unknown organization.")
		return
	}
	serialized, err := yaml.Marshal(&config_proto.Config{
		Version: org_config_obj.Version,
		Client:  org_config_obj.Client,
	})
	if err != nil {
		orgsError(w, http.StatusInternalServerError, "Could not build the client config.")
		return
	}
	name := "client." + utils.NormalizedOrgId(id) + ".config.yaml"
	if utils.IsRootOrg(id) {
		name = "client.root.config.yaml"
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(serialized)
}

func orgAudit(r *http.Request, config_obj *config_proto.Config,
	principal, op string, details *ordereddict.Dict) {
	if err := services.LogAudit(r.Context(), config_obj, principal, op, details); err != nil {
		logging.GetLogger(config_obj, &logging.FrontendComponent).
			Error("<red>%v</> %v %v", op, principal, details)
	}
}

func orgCreate(w http.ResponseWriter, r *http.Request,
	root_config_obj *config_proto.Config, org_manager services.OrgManager,
	principal, name string) {

	name, err := orgs.ValidateOrgName(name)
	if err != nil {
		orgsError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, o := range org_manager.ListOrgs() {
		if strings.EqualFold(o.Name, name) {
			orgsError(w, http.StatusConflict, "An organization with that name already exists.")
			return
		}
	}

	record, err := org_manager.CreateNewOrg(name, "", services.RandomNonce)
	if err != nil {
		orgsError(w, http.StatusInternalServerError, "Could not create the organization: "+err.Error())
		return
	}
	orgAudit(r, root_config_obj, principal, "org_create", ordereddict.NewDict().
		Set("name", record.Name).
		Set("org_id", record.Id))

	// Like Server.Orgs.NewOrg: the creator administers the new org, so
	// it shows up in their org switcher straight away.
	err = services.GrantUserToOrg(r.Context(), principal, principal,
		[]string{record.Id}, &acl_proto.ApiClientACL{Roles: []string{"administrator"}})
	if err != nil {
		logging.GetLogger(root_config_obj, &logging.FrontendComponent).
			Error("org_create: could not add %v to %v: %v", principal, record.Id, err)
	}

	orgsJSON(w, http.StatusOK, map[string]interface{}{
		"org": atlOrg{Id: record.Id, Name: record.Name, Users: 1},
	})
}

func orgRename(w http.ResponseWriter, r *http.Request,
	root_config_obj *config_proto.Config, org_manager services.OrgManager,
	principal, id, name string) {

	if utils.IsRootOrg(id) {
		orgsError(w, http.StatusBadRequest, "The root organization can not be renamed.")
		return
	}
	name, err := orgs.ValidateOrgName(name)
	if err != nil {
		orgsError(w, http.StatusBadRequest, err.Error())
		return
	}
	old, err := org_manager.GetOrg(id)
	if err != nil {
		orgsError(w, http.StatusNotFound, "Unknown organization.")
		return
	}
	old_name := old.Name
	for _, o := range org_manager.ListOrgs() {
		if strings.EqualFold(o.Name, name) && utils.NormalizedOrgId(o.Id) != utils.NormalizedOrgId(id) {
			orgsError(w, http.StatusConflict, "An organization with that name already exists.")
			return
		}
	}

	record, err := org_manager.RenameOrg(id, name)
	if err != nil {
		orgsError(w, http.StatusBadRequest, err.Error())
		return
	}
	orgAudit(r, root_config_obj, principal, "org_rename", ordereddict.NewDict().
		Set("org_id", record.Id).
		Set("old_name", old_name).
		Set("name", record.Name))
	orgsJSON(w, http.StatusOK, map[string]interface{}{
		"org": atlOrg{Id: record.Id, Name: record.Name},
	})
}

func orgDelete(w http.ResponseWriter, r *http.Request,
	root_config_obj *config_proto.Config, org_manager services.OrgManager,
	principal, id, confirm string) {

	if utils.IsRootOrg(id) {
		orgsError(w, http.StatusBadRequest, "The root organization can not be deleted.")
		return
	}
	record, err := org_manager.GetOrg(id)
	if err != nil {
		orgsError(w, http.StatusNotFound, "Unknown organization.")
		return
	}
	if record.Redirected {
		orgsError(w, http.StatusBadRequest, "Redirected organizations are removed from the server config.")
		return
	}
	// The console asks the admin to type the org's name; the server
	// checks it too so a stray request can not wipe an org.
	if strings.TrimSpace(confirm) != record.Name {
		orgsError(w, http.StatusBadRequest, "Type the organization's name to confirm.")
		return
	}

	name := record.Name
	err = org_manager.DeleteOrg(r.Context(), principal, record.Id)
	if err != nil {
		orgsError(w, http.StatusInternalServerError, "Could not delete the organization: "+err.Error())
		return
	}
	orgAudit(r, root_config_obj, principal, "org_delete", ordereddict.NewDict().
		Set("org_id", id).
		Set("name", name))
	orgsJSON(w, http.StatusOK, map[string]interface{}{"deleted": id})
}
