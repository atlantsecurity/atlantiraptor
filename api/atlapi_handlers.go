package api

// REST API for SIEM/SOAR integration: /api/atl/v1/...
//
// Authentication is a bearer API key (see atlapi_keys.go). Every
// endpoint runs a fixed VQL query as the key's own principal, with the
// caller's values bound as variables (never spliced into the query), so
// all permission checks, including artifacts' required_permissions,
// apply exactly as for console users. Writes are audited.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	stdjson "encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/api/authenticators"
	api_utils "www.velocidex.com/golang/velociraptor/api/utils"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	vjson "www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/acl_managers"
	"www.velocidex.com/golang/vfilter"
)

const (
	apiMaxRows      = 5000
	apiDefaultRows  = 500
	apiMaxBody      = 1 << 20
	apiQueryTimeout = 60 * time.Second
	casePrefix      = "atl-case:v1:"
)

var (
	clientIdRe = regexp.MustCompile(`^C\.[0-9a-f]{16}(-[A-Za-z0-9]+)?$`)
	flowIdRe   = regexp.MustCompile(`^F\.[A-Z0-9]{6,32}$`)
	huntIdRe   = regexp.MustCompile(`^H\.[A-Z0-9]{6,32}$`)
	notebookRe = regexp.MustCompile(`^N\.[A-Za-z0-9.]{3,64}$`)
	artifactRe = regexp.MustCompile(`^[A-Za-z0-9_.]{1,200}(/[A-Za-z0-9_ .\-]{1,100})?$`)
	labelRe    = regexp.MustCompile(`^[A-Za-z0-9_.:\- ]{1,64}$`)
	osRe       = regexp.MustCompile(`^(WINDOWS|LINUX|OSX)$`)
	paramKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	iocTypes   = []string{"sha256", "sha1", "md5", "ip", "domain", "path", "filename"}
)

type apiCtx struct {
	w      http.ResponseWriter
	r      *http.Request
	key    APIKey
	root   *config_proto.Config
	org    *config_proto.Config
	parts  []string
	method string
}

func apiWrite(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	data, err := vjson.MarshalWithOptions(v, vjson.DefaultEncOpts())
	if err != nil {
		data = []byte(`{"error":"encoding failed"}`)
	}
	_, _ = w.Write(data)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	apiWrite(w, status, map[string]string{"error": msg})
}

// runAPIQuery runs a fixed query as principal and returns up to max rows.
func runAPIQuery(ctx context.Context, config_obj *config_proto.Config, principal string,
	env *ordereddict.Dict, query string, max int) ([]*ordereddict.Dict, error) {
	return runAPIQueryWithACL(ctx, config_obj, acl_managers.NewServerACLManager(config_obj, principal), env, query, max)
}

func runAPIQueryWithACL(ctx context.Context, config_obj *config_proto.Config, acl vql_subsystem.ACLManager,
	env *ordereddict.Dict, query string, max int) ([]*ordereddict.Dict, error) {

	manager, err := services.GetRepositoryManager(config_obj)
	if err != nil {
		return nil, err
	}
	scope := manager.BuildScope(services.ScopeBuilder{
		Config:     config_obj,
		Env:        env,
		ACLManager: acl,
		Logger:     logging.NewPlainLogger(config_obj, &logging.ToolComponent),
	})
	defer scope.Close()

	vql, err := vfilter.Parse(query)
	if err != nil {
		return nil, err
	}
	sub_ctx, cancel := context.WithTimeout(ctx, apiQueryTimeout)
	defer cancel()

	rows := []*ordereddict.Dict{}
	for row := range vql.Eval(sub_ctx, scope) {
		d := ordereddict.NewDict()
		for _, column := range scope.GetMembers(row) {
			value, _ := scope.Associative(row, column)
			d.Set(column, value)
		}
		rows = append(rows, d)
		if max > 0 && len(rows) >= max {
			break
		}
	}
	return rows, nil
}

func intParam(r *http.Request, name string, def, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func newToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func oneLineText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > max {
		return string([]rune(s)[:max])
	}
	return s
}

func (c *apiCtx) audit(op string, details *ordereddict.Dict) {
	details.Set("api_key", c.key.Name).Set("api_key_id", c.key.ID).Set("remote", c.r.RemoteAddr)
	if err := services.LogAudit(c.r.Context(), c.org, c.key.Principal(), op, details); err != nil {
		logging.GetLogger(c.org, &logging.FrontendComponent).Error("%v %v", op, c.key.Principal())
	}
}

func (c *apiCtx) query(q string, env *ordereddict.Dict, max int) ([]*ordereddict.Dict, bool) {
	rows, err := runAPIQuery(c.r.Context(), c.org, c.key.Principal(), env, q, max)
	if err != nil {
		logging.GetLogger(c.org, &logging.FrontendComponent).Info("atl api %v: %v", c.key.Principal(), err)
		apiError(c.w, http.StatusBadRequest, "The request could not be run")
		return nil, false
	}
	return rows, true
}

func decodeBody(c *apiCtx, v interface{}) bool {
	dec := stdjson.NewDecoder(http.MaxBytesReader(c.w, c.r.Body, apiMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(c.w, http.StatusBadRequest, "Bad request body: expected JSON with the documented fields")
		return false
	}
	return true
}

// AtlAPIHandler serves /api/atl/v1/.
func AtlAPIHandler(config_obj *config_proto.Config) http.Handler {
	prefix := api_utils.GetBasePath(config_obj, "/api/atl/v1/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		if rest == "openapi.yaml" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write([]byte(atlOpenAPISpec))
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			apiError(w, http.StatusUnauthorized, "Send an API key: Authorization: Bearer atl_...")
			return
		}
		org_manager, err := services.GetOrgManager()
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "Server not ready")
			return
		}
		root, err := org_manager.GetOrgConfig(services.ROOT_ORG_ID)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "Server not ready")
			return
		}
		// A valid key always works; the per-address throttle only slows
		// down repeated failures, so others' failures can't lock it out.
		// Behind a reverse proxy the TCP peer is the proxy, so use the
		// proxy-aware client address (GUI.forwarded_proxy_header).
		ip := remoteIP(r)
		if client := authenticators.ClientIP(config_obj, r); client != nil {
			ip = client.String()
		}
		key, err := VerifyAPIKey(root, strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")), time.Now())
		if err != nil {
			if authBlocked(ip, time.Now()) {
				w.Header().Set("Retry-After", "60")
				apiError(w, http.StatusTooManyRequests, "Too many failed attempts")
				return
			}
			authFailed(ip, time.Now())
			logging.GetLogger(root, &logging.FrontendComponent).Info("atl api: rejected API key from %v", ip)
			apiError(w, http.StatusUnauthorized, errBadToken.Error())
			return
		}
		if !authenticators.IPAllowedByEntries(authenticators.ClientIP(config_obj, r), key.AllowedNetworks) {
			// Answer as for a bad key, so a stolen key can't be confirmed
			// from elsewhere, and count it as a failed attempt.
			authenticators.LogNetworkDenied(root, "api-key", "key "+key.ID, authenticators.ClientIP(config_obj, r), r)
			authFailed(ip, time.Now())
			apiError(w, http.StatusUnauthorized, errBadToken.Error())
			return
		}
		if !allowRequest(key, time.Now()) {
			w.Header().Set("Retry-After", "1")
			apiError(w, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		org, err := org_manager.GetOrgConfig(key.OrgId)
		if err != nil {
			apiError(w, http.StatusForbidden, "The key's org no longer exists")
			return
		}

		parts := []string{}
		for _, p := range strings.Split(strings.Trim(rest, "/"), "/") {
			if p != "" {
				parts = append(parts, p)
			}
		}
		routeAPI(&apiCtx{w: w, r: r, key: key, root: root, org: org, parts: parts, method: r.Method})
	})
}

func routeAPI(c *apiCtx) {
	p := c.parts
	get := c.method == http.MethodGet
	post := c.method == http.MethodPost
	switch {
	case len(p) == 1 && p[0] == "whoami" && get:
		apiWrite(c.w, 200, map[string]interface{}{"key": c.key.Public(), "principal": c.key.Principal()})
	case len(p) == 1 && p[0] == "actions" && get:
		apiWrite(c.w, 200, map[string]interface{}{"data": apiActions})
	case len(p) == 2 && p[0] == "actions" && get:
		if a := findAPIAction(p[1]); a != nil {
			apiWrite(c.w, 200, map[string]interface{}{"data": a})
		} else {
			apiError(c.w, 404, "No such action")
		}
	case len(p) == 3 && p[0] == "actions" && p[2] == "run" && post:
		runAction(c, p[1])
	case len(p) == 1 && p[0] == "alerts" && get:
		listAlerts(c)
	case len(p) == 1 && p[0] == "clients" && get:
		listClients(c)
	case len(p) == 3 && p[0] == "clients" && p[2] == "flows" && get:
		listFlows(c, p[1])
	case len(p) == 4 && p[0] == "clients" && p[2] == "flows" && get:
		getFlow(c, p[1], p[3])
	case len(p) == 5 && p[0] == "clients" && p[2] == "flows" && p[4] == "results" && get:
		flowResults(c, p[1], p[3])
	case len(p) == 1 && p[0] == "collections" && post:
		startCollection(c)
	case len(p) == 1 && p[0] == "hunts" && get:
		listHunts(c, "")
	case len(p) == 2 && p[0] == "hunts" && get:
		listHunts(c, p[1])
	case len(p) == 3 && p[0] == "hunts" && p[2] == "results" && get:
		huntResults(c, p[1])
	case len(p) == 1 && p[0] == "hunts" && post:
		startHunt(c)
	case len(p) == 1 && p[0] == "ioc-sweeps" && post:
		startIOCSweep(c)
	case len(p) == 1 && p[0] == "artifacts" && get:
		listArtifacts(c)
	case len(p) == 1 && p[0] == "cases" && get:
		listCases(c, "")
	case len(p) == 2 && p[0] == "cases" && get:
		listCases(c, p[1])
	case len(p) == 1 && p[0] == "rapid-hunts" && post:
		startRapidHunt(c)
	case len(p) == 1 && p[0] == "rapid-hunts" && get:
		listRapidHunts(c)
	case len(p) == 2 && p[0] == "rapid-hunts" && get:
		getRapidHunt(c, p[1])
	case len(p) == 1 && p[0] == "approvals" && get:
		listApprovals(c)
	case len(p) == 3 && p[0] == "approvals" && (p[2] == "approve" || p[2] == "reject") && post:
		decideApproval(c, p[1], p[2] == "approve")
	case len(p) == 3 && p[0] == "hunts" && (p[2] == "stop" || p[2] == "start") && post:
		controlHunt(c, p[1], p[2])
	case len(p) == 2 && p[0] == "clients" && get:
		getClient(c, p[1])
	case len(p) == 3 && p[0] == "clients" && p[2] == "labels" && post:
		labelClient(c, p[1])
	case len(p) == 5 && p[0] == "clients" && p[2] == "flows" && p[4] == "cancel" && post:
		cancelFlow(c, p[1], p[3])
	case len(p) == 5 && p[0] == "clients" && p[2] == "flows" && p[4] == "uploads" && get:
		listUploads(c, p[1], p[3])
	case len(p) == 6 && p[0] == "clients" && p[2] == "flows" && p[4] == "uploads" && get:
		downloadUpload(c, p[1], p[3], p[5])
	case len(p) == 2 && p[0] == "artifacts" && get:
		getArtifact(c, p[1])
	case len(p) == 1 && p[0] == "stats" && get:
		fleetStats(c)
	case len(p) == 1 && p[0] == "query" && post:
		runAnalysisQuery(c)
	default:
		apiError(c.w, 404, "No such endpoint. See /api/atl/v1/openapi.yaml")
	}
}

// ---------------------------------------------------------------- reads

func listAlerts(c *apiCtx) {
	since, _ := strconv.ParseInt(c.r.URL.Query().Get("since"), 10, 64)
	if since <= 0 {
		since = time.Now().Add(-24 * time.Hour).Unix()
	}
	limit := intParam(c.r, "limit", apiDefaultRows, apiMaxRows)
	env := ordereddict.NewDict().Set("Since", since).Set("End", time.Now().Add(time.Minute).Unix())
	// Read a bounded number of rows: the limit plus headroom to finish
	// the last second.
	rows, ok := c.query(`SELECT * FROM source(artifact="Server.Internal.Alerts", start_time=Since, end_time=End)`, env, limit+2000)
	if !ok {
		return
	}
	// Return rows strictly after the cursor; when the limit is reached,
	// finish the current second so a cursor never splits one.
	out := []*ordereddict.Dict{}
	next := since
	for _, row := range rows {
		ts := rowTimestamp(row)
		if ts <= since {
			continue
		}
		if len(out) >= limit && ts != next {
			break
		}
		out = append(out, row)
		if ts > next {
			next = ts
		}
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": out, "next_since": next, "count": len(out)})
}

func rowTimestamp(row *ordereddict.Dict) int64 {
	for _, k := range []string{"_ts", "timestamp"} {
		if v, ok := row.Get(k); ok {
			switch t := v.(type) {
			case int64:
				return t
			case uint64:
				return int64(t)
			case float64:
				return int64(t)
			case time.Time:
				return t.Unix()
			case string:
				if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
					return parsed.Unix()
				}
				if n, err := strconv.ParseInt(t, 10, 64); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func listClients(c *apiCtx) {
	q := c.r.URL.Query().Get("q")
	if q == "" {
		q = "all"
	}
	if len(q) > 200 {
		apiError(c.w, 400, "q too long")
		return
	}
	rows, ok := c.query(`SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn,
		os_info.system AS os, os_info.release AS release, agent_information.version AS agent_version,
		last_seen_at, first_seen_at, last_ip, labels
		FROM clients(search=Q)`, ordereddict.NewDict().Set("Q", q), intParam(c.r, "limit", apiDefaultRows, apiMaxRows))
	if ok {
		apiWrite(c.w, 200, map[string]interface{}{"data": rows})
	}
}

func listFlows(c *apiCtx, client string) {
	if !clientIdRe.MatchString(client) {
		apiError(c.w, 400, "invalid client id")
		return
	}
	rows, ok := c.query(`SELECT session_id AS flow_id, request.artifacts AS artifacts, request.creator AS creator,
		state, create_time, active_time, total_collected_rows, total_uploaded_files, status
		FROM flows(client_id=ClientId)`, ordereddict.NewDict().Set("ClientId", client), intParam(c.r, "limit", 100, apiMaxRows))
	if ok {
		apiWrite(c.w, 200, map[string]interface{}{"data": rows})
	}
}

func getFlow(c *apiCtx, client, flow string) {
	if !clientIdRe.MatchString(client) || !flowIdRe.MatchString(flow) {
		apiError(c.w, 400, "invalid client or flow id")
		return
	}
	rows, ok := c.query(`SELECT session_id AS flow_id, request.artifacts AS artifacts, request.creator AS creator,
		state, status, create_time, active_time, total_collected_rows, total_uploaded_files,
		artifacts_with_results
		FROM flows(client_id=ClientId, flow_id=FlowId)`,
		ordereddict.NewDict().Set("ClientId", client).Set("FlowId", flow), 1)
	if !ok {
		return
	}
	if len(rows) == 0 {
		apiError(c.w, 404, "No such collection")
		return
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": rows[0]})
}

func flowResults(c *apiCtx, client, flow string) {
	artifact := c.r.URL.Query().Get("artifact")
	if !clientIdRe.MatchString(client) || !flowIdRe.MatchString(flow) || !artifactRe.MatchString(artifact) {
		apiError(c.w, 400, "invalid client id, flow id or artifact")
		return
	}
	rows, ok := c.query(`SELECT * FROM source(client_id=ClientId, flow_id=FlowId, artifact=Artifact)`,
		ordereddict.NewDict().Set("ClientId", client).Set("FlowId", flow).Set("Artifact", artifact),
		intParam(c.r, "limit", apiDefaultRows, apiMaxRows))
	if ok {
		apiWrite(c.w, 200, map[string]interface{}{"data": rows})
	}
}

func listHunts(c *apiCtx, id string) {
	env := ordereddict.NewDict()
	q := `SELECT hunt_id, hunt_description, state, creator, create_time, start_time, expires,
		start_request.artifacts AS artifacts, tags, stats FROM hunts()`
	max := intParam(c.r, "limit", 100, apiMaxRows)
	if id != "" {
		if !huntIdRe.MatchString(id) {
			apiError(c.w, 400, "invalid hunt id")
			return
		}
		env.Set("HuntId", id)
		q = `SELECT hunt_id, hunt_description, state, creator, create_time, start_time, expires,
			start_request.artifacts AS artifacts, tags, stats, condition FROM hunts(hunt_id=HuntId)`
		max = 1
	}
	rows, ok := c.query(q, env, max)
	if !ok {
		return
	}
	if id != "" {
		if len(rows) == 0 {
			apiError(c.w, 404, "No such hunt")
			return
		}
		apiWrite(c.w, 200, map[string]interface{}{"data": rows[0]})
		return
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": rows})
}

func huntResults(c *apiCtx, id string) {
	artifact := c.r.URL.Query().Get("artifact")
	if !huntIdRe.MatchString(id) || !artifactRe.MatchString(artifact) {
		apiError(c.w, 400, "invalid hunt id or artifact")
		return
	}
	rows, ok := c.query(`SELECT * FROM hunt_results(hunt_id=HuntId, artifact=Artifact)`,
		ordereddict.NewDict().Set("HuntId", id).Set("Artifact", artifact),
		intParam(c.r, "limit", apiDefaultRows, apiMaxRows))
	if ok {
		apiWrite(c.w, 200, map[string]interface{}{"data": rows})
	}
}

func listArtifacts(c *apiCtx) {
	t := strings.ToUpper(c.r.URL.Query().Get("type"))
	if t == "" {
		t = "CLIENT"
	}
	if t != "CLIENT" && t != "SERVER" && t != "CLIENT_EVENT" && t != "SERVER_EVENT" {
		apiError(c.w, 400, "type must be CLIENT, SERVER, CLIENT_EVENT or SERVER_EVENT")
		return
	}
	name := c.r.URL.Query().Get("name")
	if len(name) > 200 {
		apiError(c.w, 400, "name too long")
		return
	}
	rows, ok := c.query(`SELECT name, description, type, parameters.name AS parameters, required_permissions
		FROM artifact_definitions() WHERE type =~ ("^" + Type + "$") AND name =~ NameRe`,
		ordereddict.NewDict().Set("Type", t).Set("NameRe", "(?i)"+regexp.QuoteMeta(name)),
		intParam(c.r, "limit", apiDefaultRows, apiMaxRows))
	if ok {
		apiWrite(c.w, 200, map[string]interface{}{"data": rows})
	}
}

func listCases(c *apiCtx, id string) {
	if id != "" && !notebookRe.MatchString(id) {
		apiError(c.w, 400, "invalid case id")
		return
	}
	rows, ok := c.query(`SELECT * FROM notebooks()`, ordereddict.NewDict(), apiMaxRows)
	if !ok {
		return
	}
	cases := []map[string]interface{}{}
	for _, row := range rows {
		desc := fmt.Sprint(firstOf(row, "description", "Description"))
		if !strings.HasPrefix(desc, casePrefix) {
			continue
		}
		nb := fmt.Sprint(firstOf(row, "notebook_id", "NotebookId"))
		if id != "" && nb != id {
			continue
		}
		var record interface{}
		if err := stdjson.Unmarshal([]byte(desc[len(casePrefix):]), &record); err != nil {
			continue
		}
		cases = append(cases, map[string]interface{}{
			"case_id": nb, "creator": firstOf(row, "creator", "Creator"),
			"modified_time": firstOf(row, "modified_time", "ModifiedTime"), "case": record,
		})
	}
	if id != "" {
		if len(cases) == 0 {
			apiError(c.w, 404, "No such case")
			return
		}
		apiWrite(c.w, 200, map[string]interface{}{"data": cases[0]})
		return
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": cases})
}

func firstOf(row *ordereddict.Dict, keys ...string) interface{} {
	for _, k := range keys {
		if v, ok := row.Get(k); ok {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------- writes

const maxTargetClients = 100

type apiTarget struct {
	ClientId      string   `json:"client_id,omitempty"`
	ClientIds     []string `json:"client_ids,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	ExcludeLabels []string `json:"exclude_labels,omitempty"`
	OS            string   `json:"os,omitempty"`
	All           bool     `json:"all,omitempty"`
}

// clients returns the explicitly named clients (deduplicated), if any.
func (t apiTarget) clients() []string {
	out := []string{}
	for _, id := range append([]string{t.ClientId}, t.ClientIds...) {
		if id != "" && !utils.InString(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// labelClients sets (or removes) one label on every named client and
// reports whether all of them took it.
func (c *apiCtx) labelClients(ids []string, label, op string) bool {
	rows, err := runAPIQuery(c.r.Context(), c.org, c.key.Principal(),
		ordereddict.NewDict().Set("Ids", ids).Set("Label", label).Set("Op", op),
		`SELECT label(client_id=_value, labels=[Label], op=Op) AS L FROM foreach(row=Ids)`, len(ids))
	if err != nil || len(rows) != len(ids) {
		return false
	}
	for _, row := range rows {
		if l, _ := row.Get("L"); utils.IsNil(l) || l == false {
			return false
		}
	}
	return true
}

// huntOnClients aims a hunt at exactly the named clients through a fresh
// label. The label goes on first so a running hunt sees the clients; if
// the hunt can't be created the label is taken off again.
func (c *apiCtx) huntOnClients(h huntRequest, ids []string, label string) (string, bool) {
	if !c.labelClients(ids, label, "set") {
		c.labelClients(ids, label, "remove")
		apiError(c.w, http.StatusForbidden, "The clients could not be labelled. The key may lack the label permission.")
		return "", false
	}
	h.Target = apiTarget{Labels: []string{label}}
	id, ok := c.hunt(h)
	if !ok {
		c.labelClients(ids, label, "remove")
	}
	return id, ok
}

// huntTarget starts a hunt on the request's target, using a fresh label
// when the target is a list of clients.
func (c *apiCtx) huntTarget(h huntRequest) (string, bool) {
	if ids := h.Target.clients(); len(ids) > 0 {
		return c.huntOnClients(h, ids, "apitarget-"+newToken()+newToken())
	}
	return c.hunt(h)
}

func (t apiTarget) validate() string {
	modes := 0
	if t.ClientId != "" {
		modes++
		if !clientIdRe.MatchString(t.ClientId) {
			return "invalid client_id"
		}
	}
	if len(t.ClientIds) > 0 {
		modes++
		if len(t.ClientIds) > maxTargetClients {
			return fmt.Sprintf("at most %d client_ids; use labels or os for more", maxTargetClients)
		}
		for _, id := range t.ClientIds {
			if !clientIdRe.MatchString(id) {
				return "invalid client id " + id
			}
		}
	}
	if len(t.Labels) > 0 {
		modes++
	}
	if t.OS != "" {
		modes++
		if !osRe.MatchString(t.OS) {
			return "os must be WINDOWS, LINUX or OSX"
		}
	}
	if t.All {
		modes++
	}
	if modes != 1 {
		return "target needs exactly one of client_id, client_ids, labels, os or all"
	}
	for _, l := range append(append([]string{}, t.Labels...), t.ExcludeLabels...) {
		if !labelRe.MatchString(l) {
			return "invalid label " + l
		}
		// Labels that aim response hunts are managed by Atlantiraptor.
		if reservedLabels.MatchString(l) {
			return "labels starting with response- or apitarget- can't be targeted directly"
		}
	}
	return ""
}

type artifactParams map[string]map[string]string

func buildSpec(artifacts []string, params artifactParams) (*ordereddict.Dict, string) {
	spec := ordereddict.NewDict()
	for _, a := range artifacts {
		if !artifactRe.MatchString(a) {
			return nil, "invalid artifact name " + a
		}
		env := ordereddict.NewDict()
		for k, v := range params[a] {
			if !paramKeyRe.MatchString(k) || len(v) > 64*1024 {
				return nil, "invalid parameter " + k
			}
			env.Set(k, v)
		}
		spec.Set(a, env)
	}
	for a := range params {
		if !utils.InString(artifacts, a) {
			return nil, "parameters given for an artifact that is not launched: " + a
		}
	}
	return spec, ""
}

func extractID(rows []*ordereddict.Dict, column string, keys ...string) string {
	if len(rows) == 0 {
		return ""
	}
	v, _ := rows[0].Get(column)
	data, err := vjson.MarshalWithOptions(v, vjson.DefaultEncOpts())
	if err != nil {
		return ""
	}
	var m map[string]interface{}
	if stdjson.Unmarshal(data, &m) != nil {
		return ""
	}
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (c *apiCtx) collect(client string, artifacts []string, spec *ordereddict.Dict, userData string) (string, bool) {
	rows, ok := c.query(`SELECT collect_client(client_id=ClientId, artifacts=Artifacts, spec=Spec, urgent=TRUE, user_data=UserData) AS Flow FROM scope()`,
		ordereddict.NewDict().Set("ClientId", client).Set("Artifacts", artifacts).Set("Spec", spec).Set("UserData", userData), 1)
	if !ok {
		return "", false
	}
	id := extractID(rows, "Flow", "flow_id", "FlowId", "session_id")
	if id == "" {
		apiError(c.w, http.StatusForbidden, "The collection was not started. The key may lack permission for these artifacts.")
		return "", false
	}
	return id, true
}

type huntRequest struct {
	Description string
	Artifacts   []string
	Spec        *ordereddict.Dict
	Target      apiTarget
	Tags        []string
	Pause       bool
	UserData    string
	// Without it the hunt stops after the default (one hour).
	RunUntilStopped bool
}

func (c *apiCtx) hunt(h huntRequest) (string, bool) {
	env := ordereddict.NewDict().
		Set("Description", h.Description).Set("Artifacts", h.Artifacts).Set("Spec", h.Spec).
		Set("Tags", h.Tags).Set("Pause", h.Pause).Set("UserData", h.UserData).
		Set("Labels", h.Target.Labels).Set("Exclude", h.Target.ExcludeLabels).Set("OS", h.Target.OS)
	expires := ""
	if h.RunUntilStopped {
		// Ten years: effectively until someone stops it.
		expires = ", expires=now() + 315360000"
	}
	rows, ok := c.query(`SELECT hunt(description=Description, artifacts=Artifacts, spec=Spec, tags=Tags,
		pause=Pause, include_labels=Labels, exclude_labels=Exclude, os=OS, user_data=UserData`+expires+`) AS Hunt FROM scope()`, env, 1)
	if !ok {
		return "", false
	}
	id := extractID(rows, "Hunt", "hunt_id", "HuntId")
	if id == "" {
		apiError(c.w, http.StatusForbidden, "The hunt was not created. The key may lack permission for these artifacts.")
		return "", false
	}
	return id, true
}

// Permissions that mark an artifact as one that changes endpoints.
var endpointChangingPerms = []string{"EXECVE", "FILESYSTEM_WRITE", "NETWORK", "MACHINE_STATE"}

// refuseResponseArtifacts keeps response artifacts out of the generic
// /collections, /hunts endpoints, so they only run through
// /actions/{id}/run with its dry run, reason and approval rules.
func (c *apiCtx) refuseResponseArtifacts(artifacts []string) bool {
	responseArtifacts := []string{}
	for _, a := range apiActions {
		if a.Kind == "response" {
			responseArtifacts = append(responseArtifacts, a.Artifacts...)
		}
	}
	manager, err := services.GetRepositoryManager(c.org)
	if err != nil {
		apiError(c.w, http.StatusServiceUnavailable, "Server not ready")
		return true
	}
	repo, err := manager.GetGlobalRepository(c.org)
	if err != nil {
		apiError(c.w, http.StatusServiceUnavailable, "Server not ready")
		return true
	}
	// Check every artifact the request would run, including the ones it
	// calls, so a wrapper artifact can't smuggle a response artifact in.
	names := []string{}
	for _, a := range artifacts {
		names = append(names, strings.SplitN(a, "/", 2)[0])
	}
	launcher, err := services.GetLauncher(c.org)
	if err != nil {
		apiError(c.w, http.StatusServiceUnavailable, "Server not ready")
		return true
	}
	deps, err := launcher.GetDependentArtifacts(c.r.Context(), c.org, repo, names)
	if err != nil {
		apiError(c.w, http.StatusBadRequest, "Unknown artifact or artifact dependency")
		return true
	}
	for _, d := range deps {
		if !utils.InString(names, d) {
			names = append(names, d)
		}
	}
	for _, name := range names {
		refuse := utils.InString(responseArtifacts, name)
		if def, ok := repo.Get(c.r.Context(), c.org, name); ok && def != nil {
			for _, p := range append(append([]string{}, def.RequiredPermissions...), def.ImpliedPermissions...) {
				if utils.InString(endpointChangingPerms, strings.ToUpper(p)) {
					refuse = true
				}
			}
		}
		if refuse {
			apiError(c.w, http.StatusForbidden, name+" changes endpoints. Run it through POST /actions/{id}/run, "+
				"which applies dry run, reason and approval rules.")
			return true
		}
	}
	return false
}

func startCollection(c *apiCtx) {
	var body struct {
		ClientId   string         `json:"client_id"`
		Artifacts  []string       `json:"artifacts"`
		Parameters artifactParams `json:"parameters,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	if !clientIdRe.MatchString(body.ClientId) || len(body.Artifacts) == 0 || len(body.Artifacts) > 50 {
		apiError(c.w, 400, "client_id and 1-50 artifacts are required")
		return
	}
	spec, msg := buildSpec(body.Artifacts, body.Parameters)
	if msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	if c.refuseResponseArtifacts(body.Artifacts) {
		return
	}
	flow, ok := c.collect(body.ClientId, body.Artifacts, spec, "")
	if !ok {
		return
	}
	c.audit("api_collect", ordereddict.NewDict().Set("client_id", body.ClientId).Set("flow_id", flow).Set("artifacts", body.Artifacts))
	apiWrite(c.w, 201, map[string]interface{}{"data": map[string]string{"client_id": body.ClientId, "flow_id": flow}})
}

func startHunt(c *apiCtx) {
	var body struct {
		Description string         `json:"description"`
		Artifacts   []string       `json:"artifacts"`
		Parameters  artifactParams `json:"parameters,omitempty"`
		Target      apiTarget      `json:"target"`
		Paused      bool           `json:"paused,omitempty"`
		// Hunts stop after one hour unless this is set.
		RunUntilStopped bool `json:"run_until_stopped,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	if len(body.Artifacts) == 0 || len(body.Artifacts) > 50 {
		apiError(c.w, 400, "1-50 artifacts are required")
		return
	}
	if body.Target.ClientId != "" {
		apiError(c.w, 400, "use /collections for a single client, or client_ids for several")
		return
	}
	if msg := body.Target.validate(); msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	spec, msg := buildSpec(body.Artifacts, body.Parameters)
	if msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	if c.refuseResponseArtifacts(body.Artifacts) {
		return
	}
	desc := oneLineText(body.Description, 200)
	if desc == "" {
		desc = "API hunt: " + strings.Join(body.Artifacts, ", ")
	}
	id, ok := c.huntTarget(huntRequest{Description: desc + " (via API key " + c.key.Name + ")", Artifacts: body.Artifacts,
		Spec: spec, Target: body.Target, Tags: []string{"api"}, Pause: body.Paused, RunUntilStopped: body.RunUntilStopped})
	if !ok {
		return
	}
	c.audit("api_hunt", ordereddict.NewDict().Set("hunt_id", id).Set("artifacts", body.Artifacts))
	apiWrite(c.w, 201, map[string]interface{}{"data": map[string]string{"hunt_id": id}})
}

type iocItem struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

func startIOCSweep(c *apiCtx) {
	var body struct {
		Indicators  []iocItem `json:"indicators"`
		Target      apiTarget `json:"target"`
		HashGlob    string    `json:"hash_glob,omitempty"`
		RaiseAlerts *bool     `json:"raise_alerts,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	if len(body.Indicators) == 0 || len(body.Indicators) > 5000 {
		apiError(c.w, 400, "1-5000 indicators are required")
		return
	}
	if msg := body.Target.validate(); msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"Type", "Value", "Note"})
	for _, i := range body.Indicators {
		t := strings.ToLower(strings.TrimSpace(i.Type))
		if !utils.InString(iocTypes, t) || len(i.Note) > 500 {
			apiError(c.w, 400, "invalid indicator: type must be one of "+strings.Join(iocTypes, ", "))
			return
		}
		if msg := validateIOC(t, strings.TrimSpace(i.Value)); msg != "" {
			apiError(c.w, 400, "invalid "+t+" indicator: "+msg)
			return
		}
		// Keep notes from being read as spreadsheet formulas on export.
		if strings.IndexAny(i.Note, "=+-@") == 0 {
			i.Note = "'" + i.Note
		}
		_ = cw.Write([]string{t, strings.TrimSpace(i.Value), i.Note})
	}
	cw.Flush()

	params := map[string]string{"IOCs": buf.String(), "RaiseAlerts": "Y"}
	if body.RaiseAlerts != nil && !*body.RaiseAlerts {
		params["RaiseAlerts"] = "N"
	}
	if body.HashGlob != "" {
		if len(body.HashGlob) > 1024 {
			apiError(c.w, 400, "hash_glob too long")
			return
		}
		params["HashGlob"] = body.HashGlob
	}
	artifact := "Generic.Detection.IOCSweep"
	spec, _ := buildSpec([]string{artifact}, artifactParams{artifact: params})
	desc := fmt.Sprintf("IOC sweep: %d indicators (via API key %s)", len(body.Indicators), c.key.Name)

	if body.Target.ClientId != "" {
		flow, ok := c.collect(body.Target.ClientId, []string{artifact}, spec, "")
		if !ok {
			return
		}
		c.audit("api_ioc_sweep", ordereddict.NewDict().Set("client_id", body.Target.ClientId).Set("flow_id", flow).Set("indicators", len(body.Indicators)))
		apiWrite(c.w, 201, map[string]interface{}{"data": map[string]string{"client_id": body.Target.ClientId, "flow_id": flow}})
		return
	}
	id, ok := c.huntTarget(huntRequest{Description: desc, Artifacts: []string{artifact}, Spec: spec, Target: body.Target, Tags: []string{"ioc-sweep", "api"}})
	if !ok {
		return
	}
	c.audit("api_ioc_sweep", ordereddict.NewDict().Set("hunt_id", id).Set("indicators", len(body.Indicators)))
	apiWrite(c.w, 201, map[string]interface{}{"data": map[string]string{"hunt_id": id}})
}

// Validators per indicator type, so values match as data on endpoints.
var (
	hexRe    = map[string]*regexp.Regexp{"md5": regexp.MustCompile(`^[0-9a-fA-F]{32}$`), "sha1": regexp.MustCompile(`^[0-9a-fA-F]{40}$`), "sha256": regexp.MustCompile(`^[0-9a-fA-F]{64}$`)}
	domainRe = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9\-]{2,63}\.?$`)
)

func validateIOC(t, v string) string {
	if v == "" || len(v) > 2048 || strings.ContainsAny(v, "\r\n\x00") {
		return "empty, too long or multi-line"
	}
	switch t {
	case "md5", "sha1", "sha256":
		if !hexRe[t].MatchString(v) {
			return "not a " + t + " hex digest"
		}
	case "ip":
		if net.ParseIP(v) == nil {
			return "not an IP address"
		}
	case "domain":
		if !domainRe.MatchString(v) {
			return "not a domain name"
		}
	}
	return ""
}

// approvalRequired reads the console's two-person approval policy.
// If it can't be read, approval is required.
func approvalRequired(c *apiCtx) bool {
	rows, err := runAPIQuery(c.r.Context(), c.org, utils.GetSuperuserName(c.org), ordereddict.NewDict(),
		`SELECT server_metadata().atl_response_require_approval AS V FROM scope()`, 1)
	if err != nil || len(rows) == 0 {
		return true
	}
	v, _ := rows[0].Get("V")
	return fmt.Sprint(v) == "Y"
}

func runAction(c *apiCtx, id string) {
	action := findAPIAction(id)
	if action == nil {
		apiError(c.w, 404, "No such action. See GET /api/atl/v1/actions")
		return
	}
	var body struct {
		Target     apiTarget         `json:"target"`
		Parameters map[string]string `json:"parameters,omitempty"`
		DryRun     *bool             `json:"dry_run,omitempty"`
		Reason     string            `json:"reason,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	if msg := body.Target.validate(); msg != "" {
		apiError(c.w, 400, msg)
		return
	}

	params := map[string]string{}
	for k, v := range action.Fixed {
		params[k] = v
	}
	for k, v := range body.Parameters {
		known := false
		for _, f := range action.Fields {
			if f.Key == k {
				known = true
			}
		}
		if !known {
			apiError(c.w, 400, "unknown parameter "+k+" for action "+id)
			return
		}
		params[k] = v
	}
	for _, f := range action.Fields {
		if _, ok := params[f.Key]; !ok && f.Default != "" {
			params[f.Key] = f.Default
		}
		if f.Required && strings.TrimSpace(params[f.Key]) == "" {
			apiError(c.w, 400, "parameter "+f.Key+" is required")
			return
		}
	}

	// Dry run by default when the action supports it.
	dryRun := action.ArmParam != "" && (body.DryRun == nil || *body.DryRun)
	if action.ArmParam != "" {
		params[action.ArmParam] = map[bool]string{true: "N", false: "Y"}[dryRun]
	}
	live := action.Kind == "response" && action.Live && !dryRun
	reason := oneLineText(body.Reason, 300)
	if live && reason == "" {
		apiError(c.w, 400, "reason is required for live response actions")
		return
	}
	needsApproval := live && approvalRequired(c)

	per := artifactParams{}
	for _, a := range action.Artifacts {
		per[a] = params
	}
	spec, msg := buildSpec(action.Artifacts, per)
	if msg != "" {
		apiError(c.w, 400, msg)
		return
	}

	desc := action.Title
	if action.Kind == "response" {
		desc = "Response: " + desc
	}
	if dryRun {
		desc += " (dry run)"
	}
	desc += " (via API key " + c.key.Name + ")"
	if reason != "" {
		desc += " – reason: " + reason
	}
	tags := []string{"api", action.ID}
	if action.Kind == "response" {
		tags = append(tags, "response")
	}
	if dryRun {
		tags = append(tags, "dry-run")
	}
	if needsApproval {
		tags = append(tags, "approval:pending")
	}
	details := ordereddict.NewDict().Set("action", action.ID).Set("live", live).Set("reason", reason).
		Set("target", body.Target).Set("needs_approval", needsApproval)

	// Same request record the console writes, so the approval queue and
	// audit view show API requests like any other.
	// Named clients: one without approval runs as a direct collection;
	// several, or any waiting for approval, get one fresh one-off label
	// that a hunt targets. The request records exactly which clients, so
	// the approval queue can check the label covers just those.
	clients := body.Target.clients()
	direct := len(clients) == 1 && !needsApproval
	oneOff := ""
	if len(clients) > 0 && !direct {
		oneOff = "response-" + newToken() + newToken()
	}
	userData := ""
	if action.Kind == "response" {
		approval := "not-required"
		if needsApproval {
			approval = "required"
		}
		// key_owner lets the console refuse approval by the person who
		// created the key, so one person can't request and approve.
		rec := map[string]interface{}{"reason": reason, "requested_by": c.key.Principal(), "approval": approval,
			"key_owner": c.key.CreatedBy, "api_key": c.key.Name}
		if oneOff != "" {
			rec["one_off_label"] = oneOff
			rec["one_off_clients"] = clients
		}
		data, _ := stdjson.Marshal(map[string]interface{}{"atl_response": rec})
		userData = string(data)
	}

	if direct {
		flow, ok := c.collect(clients[0], action.Artifacts, spec, userData)
		if !ok {
			return
		}
		c.audit("api_action", details.Set("flow_id", flow))
		apiWrite(c.w, 201, map[string]interface{}{"data": map[string]interface{}{
			"client_id": clients[0], "flow_id": flow, "dry_run": dryRun,
			"status_url": "/api/atl/v1/clients/" + clients[0] + "/flows/" + flow}})
		return
	}

	h := huntRequest{Description: desc, Artifacts: action.Artifacts, Spec: spec,
		Target: body.Target, Tags: tags, Pause: needsApproval, UserData: userData}
	var huntID string
	var ok bool
	if len(clients) > 0 {
		if len(clients) == 1 {
			h.Description += " – host " + clients[0]
		} else {
			h.Description += fmt.Sprintf(" – %d hosts", len(clients))
		}
		huntID, ok = c.huntOnClients(h, clients, oneOff)
	} else {
		huntID, ok = c.hunt(h)
	}
	if !ok {
		return
	}
	c.audit("api_action", details.Set("hunt_id", huntID))
	state := "running"
	if needsApproval {
		state = "waiting_for_approval"
	}
	apiWrite(c.w, 201, map[string]interface{}{"data": map[string]interface{}{
		"hunt_id": huntID, "state": state, "dry_run": dryRun,
		"status_url": "/api/atl/v1/hunts/" + huntID}})
}
