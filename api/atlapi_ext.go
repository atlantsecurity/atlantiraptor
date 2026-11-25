package api

// More of the console's functions over /api/atl/v1, so a SIEM or SOAR
// can embed Atlantiraptor without anyone opening its console: Rapid hunt,
// approvals, hunt and flow control, client details and labels, uploaded
// files, artifact details, fleet stats and read-only analysis queries.

import (
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/hunt_dispatcher"
	"www.velocidex.com/golang/velociraptor/utils"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/acl_managers"
)

const (
	rapidArtifact    = "Generic.Detection.RapidHunt"
	rapidTag         = "rapid-hunt"
	rapidPrefix      = "Rapid hunt: "
	pendingTag       = "approval:pending"
	approvedPrefix   = "approval:approved-by:"
	rejectedPrefix   = "approval:rejected-by:"
	maxDownloadBytes = 100 << 20
)

var (
	rapidDomainRe  = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9-]{2,63}\.?$`)
	reservedLabels = regexp.MustCompile(`(?i)^(response-|apitarget-)`)
	oneOffLabelRe  = regexp.MustCompile(`^response-[0-9a-z]{12,40}$`)
)

// ------------------------------------------------------------ Rapid hunt

// rapidIndicatorProblem mirrors the console's check: a domain, URL or IP.
func rapidIndicatorProblem(v string) string {
	if v == "" || len(v) > 2048 || strings.ContainsAny(v, " \t\r\n") {
		return "indicator must be one domain, URL or IP address"
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "indicator URLs must be http or https"
		}
		if net.ParseIP(u.Hostname()) == nil && !rapidDomainRe.MatchString(u.Hostname()) {
			return "indicator URL has no valid host"
		}
		return ""
	}
	if net.ParseIP(v) != nil {
		return ""
	}
	host := strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == ':' })
	if len(host) > 0 && rapidDomainRe.MatchString(host[0]) {
		return ""
	}
	return "indicator must be a domain (example.com), URL or IP address"
}

func startRapidHunt(c *apiCtx) {
	var body struct {
		Indicator        string    `json:"indicator"`
		DaysBack         int       `json:"days_back,omitempty"`
		IncludeEventLogs *bool     `json:"include_event_logs,omitempty"`
		Target           apiTarget `json:"target,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	body.Indicator = strings.TrimSpace(body.Indicator)
	if msg := rapidIndicatorProblem(body.Indicator); msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	if body.DaysBack == 0 {
		body.DaysBack = 30
	}
	if body.DaysBack < 1 || body.DaysBack > 365 {
		apiError(c.w, 400, "days_back must be 1-365")
		return
	}
	// No target means every machine.
	target := body.Target
	if target.ClientId == "" && len(target.ClientIds) == 0 && len(target.Labels) == 0 && target.OS == "" && !target.All {
		target.All = true
	}
	if msg := target.validate(); msg != "" {
		apiError(c.w, 400, msg)
		return
	}
	logs := "Y"
	if body.IncludeEventLogs != nil && !*body.IncludeEventLogs {
		logs = "N"
	}
	spec, _ := buildSpec([]string{rapidArtifact}, artifactParams{rapidArtifact: {
		"Indicator": body.Indicator, "DaysBack": strconv.Itoa(body.DaysBack), "IncludeEventLogs": logs}})
	id, ok := c.huntTarget(huntRequest{Description: rapidPrefix + body.Indicator,
		Artifacts: []string{rapidArtifact}, Spec: spec, Target: target, Tags: []string{rapidTag, "api"}})
	if !ok {
		return
	}
	c.audit("api_rapid_hunt", ordereddict.NewDict().Set("hunt_id", id).Set("indicator", body.Indicator))
	apiWrite(c.w, 201, map[string]interface{}{"data": map[string]string{
		"hunt_id": id, "status_url": "/api/atl/v1/rapid-hunts/" + id}})
}

func listRapidHunts(c *apiCtx) {
	rows, ok := c.query(`SELECT hunt_id, hunt_description, state, create_time, creator, stats
		FROM hunts() WHERE RapidTag in tags`,
		ordereddict.NewDict().Set("RapidTag", rapidTag), apiMaxRows)
	if !ok {
		return
	}
	out := []map[string]interface{}{}
	for _, r := range rows {
		desc := fmt.Sprint(firstOf(r, "hunt_description"))
		out = append(out, map[string]interface{}{
			"hunt_id": firstOf(r, "hunt_id"), "indicator": strings.TrimPrefix(desc, rapidPrefix),
			"state": firstOf(r, "state"), "create_time": firstOf(r, "create_time"),
			"creator": firstOf(r, "creator"), "progress": huntProgress(firstOf(r, "stats")),
		})
	}
	limit := intParam(c.r, "limit", 50, 500)
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": out})
}

func huntProgress(stats interface{}) map[string]int64 {
	get := func(k string) int64 {
		if d, ok := stats.(*ordereddict.Dict); ok {
			v, _ := d.Get(k)
			n, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64)
			return n
		}
		if m, ok := stats.(map[string]interface{}); ok {
			n, _ := strconv.ParseInt(fmt.Sprint(m[k]), 10, 64)
			return n
		}
		return 0
	}
	return map[string]int64{
		"scheduled":    get("total_clients_scheduled"),
		"with_results": get("total_clients_with_results"),
		"with_errors":  get("total_clients_with_errors"),
	}
}

type rapidMachine struct {
	ClientId string                   `json:"client_id"`
	Hostname string                   `json:"hostname"`
	Sources  []string                 `json:"sources"`
	Users    []string                 `json:"users"`
	Hits     int                      `json:"hit_count"`
	Details  []map[string]interface{} `json:"hits,omitempty"`
}

func getRapidHunt(c *apiCtx, id string) {
	if !huntIdRe.MatchString(id) {
		apiError(c.w, 400, "invalid hunt id")
		return
	}
	meta, ok := c.query(`SELECT hunt_id, hunt_description, state, create_time, RapidTag in tags AS IsRapid, stats FROM hunts(hunt_id=HuntId)`,
		ordereddict.NewDict().Set("HuntId", id).Set("RapidTag", rapidTag), 1)
	if !ok {
		return
	}
	if len(meta) == 0 || firstOf(meta[0], "IsRapid") != true {
		apiError(c.w, 404, "No such rapid hunt")
		return
	}
	rows, ok := c.query(`SELECT * FROM hunt_results(hunt_id=HuntId, artifact=Artifact)`,
		ordereddict.NewDict().Set("HuntId", id).Set("Artifact", rapidArtifact), apiMaxRows)
	if !ok {
		return
	}
	withHits := c.r.URL.Query().Get("hits") != "0"
	byHost := map[string]*rapidMachine{}
	order := []string{}
	for _, r := range rows {
		cid := fmt.Sprint(firstOf(r, "ClientId"))
		m := byHost[cid]
		if m == nil {
			m = &rapidMachine{ClientId: cid, Hostname: fmt.Sprint(firstOf(r, "Fqdn")), Sources: []string{}, Users: []string{}}
			byHost[cid] = m
			order = append(order, cid)
		}
		m.Hits++
		src, user := fmt.Sprint(firstOf(r, "Source")), fmt.Sprint(firstOf(r, "User"))
		if src != "" && !utils.InString(m.Sources, src) {
			m.Sources = append(m.Sources, src)
		}
		if user != "" && !utils.InString(m.Users, user) {
			m.Users = append(m.Users, user)
		}
		if withHits {
			m.Details = append(m.Details, map[string]interface{}{
				"source": src, "time": firstOf(r, "Time"), "user": user, "process": firstOf(r, "Process"),
				"match": firstOf(r, "Match"), "detail": firstOf(r, "Detail"),
			})
		}
	}
	machines := []*rapidMachine{}
	for _, cid := range order {
		machines = append(machines, byHost[cid])
	}
	sort.SliceStable(machines, func(i, j int) bool { return machines[i].Hits > machines[j].Hits })
	desc := fmt.Sprint(firstOf(meta[0], "hunt_description"))
	apiWrite(c.w, 200, map[string]interface{}{"data": map[string]interface{}{
		"hunt_id": id, "indicator": strings.TrimPrefix(desc, rapidPrefix),
		"state": firstOf(meta[0], "state"), "create_time": firstOf(meta[0], "create_time"),
		"progress": huntProgress(firstOf(meta[0], "stats")), "matched_machines": len(machines),
		"machines": machines, "truncated": len(rows) >= apiMaxRows,
	}})
}

// ------------------------------------------------------------ Approvals

type pendingRequest struct {
	Reason      string   `json:"reason"`
	RequestedBy string   `json:"requested_by"`
	KeyOwner    string   `json:"key_owner,omitempty"`
	OneOffLabel string   `json:"one_off_label,omitempty"`
	OneOff      []string `json:"one_off_clients,omitempty"`
}

func parseRequest(userData string) pendingRequest {
	var wrap struct {
		R pendingRequest `json:"atl_response"`
	}
	_ = stdjson.Unmarshal([]byte(userData), &wrap)
	return wrap.R
}

func listApprovals(c *apiCtx) {
	rows, ok := c.query(`SELECT hunt_id, hunt_description, creator, create_time, state, tags, condition,
		start_request.artifacts AS artifacts, start_request.specs AS specs, start_request.user_data AS user_data
		FROM hunts() WHERE state = "PAUSED" AND "response" in tags AND PendingTag in tags`,
		ordereddict.NewDict().Set("PendingTag", pendingTag), 500)
	if !ok {
		return
	}
	out := []map[string]interface{}{}
	for _, r := range rows {
		req := parseRequest(fmt.Sprint(firstOf(r, "user_data")))
		out = append(out, map[string]interface{}{
			"hunt_id": firstOf(r, "hunt_id"), "description": firstOf(r, "hunt_description"),
			"creator": firstOf(r, "creator"), "create_time": firstOf(r, "create_time"),
			"state": firstOf(r, "state"), "condition": firstOf(r, "condition"),
			"artifacts": firstOf(r, "artifacts"), "specs": firstOf(r, "specs"), "request": req,
		})
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": out})
}

func decideApproval(c *apiCtx, id string, approve bool) {
	if !huntIdRe.MatchString(id) {
		apiError(c.w, 400, "invalid hunt id")
		return
	}
	if ok, _ := services.CheckAccess(c.org, c.key.Principal(), acls.START_HUNT); !ok {
		apiError(c.w, http.StatusForbidden, "The key needs a role that can start hunts to decide approvals.")
		return
	}
	dispatcher, err := services.GetHuntDispatcher(c.org)
	if err != nil {
		apiError(c.w, http.StatusServiceUnavailable, "Server not ready")
		return
	}
	hunt, pres := dispatcher.GetHunt(c.r.Context(), services.GetHuntOptions{Request: true}, id)
	if !pres || hunt == nil {
		apiError(c.w, 404, "No such hunt")
		return
	}
	if !utils.InString(hunt.Tags, pendingTag) || !utils.InString(hunt.Tags, "response") ||
		hunt.State != api_proto.Hunt_PAUSED {
		apiError(c.w, http.StatusConflict, "This request is not waiting for approval.")
		return
	}
	userData := ""
	if hunt.StartRequest != nil {
		userData = hunt.StartRequest.UserData
	}
	req := parseRequest(userData)

	// The same separation the console applies: whoever asked (or owns
	// the key that asked) can't approve.
	if approve {
		me, owner := c.key.Principal(), c.key.CreatedBy
		for _, who := range []string{hunt.Creator, req.KeyOwner} {
			if who != "" && (utils.UsernamesEqual(who, me) || utils.UsernamesEqual(who, owner)) {
				apiError(c.w, http.StatusForbidden, "The requester, or the owner of the key that made the request, can't approve it.")
				return
			}
		}
		if msg := c.checkOneOffTarget(hunt, req); msg != "" {
			apiError(c.w, http.StatusConflict, msg)
			return
		}
	}

	reason := oneLineText(c.r.URL.Query().Get("reason"), 300)
	decision := approvedPrefix
	state := api_proto.Hunt_RUNNING
	if !approve {
		decision = rejectedPrefix
		state = api_proto.Hunt_STOPPED
	}
	tags := []string{}
	for _, t := range hunt.Tags {
		if t != pendingTag {
			tags = append(tags, t)
		}
	}
	tags = append(tags, decision+c.key.Principal())

	// One change carrying both the decision and the new state; the hunt
	// dispatcher enforces the approval rules again (approval_guard.go).
	if err := dispatcher.MutateHunt(c.r.Context(), c.org, &api_proto.HuntMutation{
		HuntId: id, State: state, Tags: tags, User: c.key.Principal()}); err != nil {
		if errors.Is(err, hunt_dispatcher.ErrApproval) {
			apiError(c.w, http.StatusForbidden, err.Error())
			return
		}
		apiError(c.w, http.StatusInternalServerError, "Could not record the decision.")
		return
	}
	if !approve && oneOffLabelRe.MatchString(req.OneOffLabel) && len(req.OneOff) > 0 {
		c.labelClients(req.OneOff, req.OneOffLabel, "remove")
	}
	op := "api_approval_reject"
	if approve {
		op = "api_approval_approve"
	}
	c.audit(op, ordereddict.NewDict().Set("hunt_id", id).Set("reason", reason).Set("requested_by", hunt.Creator))
	apiWrite(c.w, 200, map[string]interface{}{"data": map[string]interface{}{
		"hunt_id": id, "approved": approve, "state": state.String()}})
}

// checkOneOffTarget makes sure a one-off label hunt is aimed at exactly
// the recorded clients before it is approved.
func (c *apiCtx) checkOneOffTarget(hunt *api_proto.Hunt, req pendingRequest) string {
	labels := []string{}
	if hunt.Condition != nil && hunt.Condition.GetLabels() != nil {
		labels = hunt.Condition.GetLabels().Label
	}
	usesOneOff := false
	for _, l := range labels {
		if strings.HasPrefix(strings.ToLower(l), "response-") {
			usesOneOff = true
		}
	}
	if !usesOneOff {
		return ""
	}
	if len(labels) != 1 || labels[0] != req.OneOffLabel || !oneOffLabelRe.MatchString(req.OneOffLabel) {
		return "The target label does not match the recorded request."
	}
	rows, err := runAPIQuery(c.r.Context(), c.org, c.key.Principal(),
		ordereddict.NewDict().Set("Q", "label:"+req.OneOffLabel),
		`SELECT client_id FROM clients(search=Q)`, maxTargetClients+5)
	if err != nil {
		return "Could not check the target clients."
	}
	got := []string{}
	for _, r := range rows {
		got = append(got, fmt.Sprint(firstOf(r, "client_id")))
	}
	want := req.OneOff
	if len(want) == 0 {
		if len(got) != 1 {
			return fmt.Sprintf("The single-host label matches %d hosts, not 1.", len(got))
		}
		return ""
	}
	sort.Strings(got)
	w := append([]string{}, want...)
	sort.Strings(w)
	if strings.Join(got, ",") != strings.Join(w, ",") {
		return fmt.Sprintf("The target label is on %d hosts, but the request named %d.", len(got), len(want))
	}
	return ""
}

// ------------------------------------------------------- Hunts and flows

func controlHunt(c *apiCtx, id, verb string) {
	if !huntIdRe.MatchString(id) {
		apiError(c.w, 400, "invalid hunt id")
		return
	}
	if verb == "start" {
		// Never start something that is waiting for approval.
		rows, ok := c.query(`SELECT PendingTag in tags AS Pending FROM hunts(hunt_id=HuntId)`,
			ordereddict.NewDict().Set("HuntId", id).Set("PendingTag", pendingTag), 1)
		if !ok {
			return
		}
		if len(rows) == 0 {
			apiError(c.w, 404, "No such hunt")
			return
		}
		if firstOf(rows[0], "Pending") == true {
			apiError(c.w, http.StatusConflict, "This hunt is waiting for approval; use /approvals/{hunt_id}/approve.")
			return
		}
	}
	rows, ok := c.query(`SELECT hunt_update(hunt_id=HuntId, stop=Stop, start=Start) AS R FROM scope()`,
		ordereddict.NewDict().Set("HuntId", id).Set("Stop", verb == "stop").Set("Start", verb == "start"), 1)
	if !ok {
		return
	}
	if len(rows) == 0 || utils.IsNil(firstOf(rows[0], "R")) {
		apiError(c.w, http.StatusForbidden, "The hunt was not changed. The key may lack permission.")
		return
	}
	c.audit("api_hunt_"+verb, ordereddict.NewDict().Set("hunt_id", id))
	apiWrite(c.w, 200, map[string]interface{}{"data": map[string]string{"hunt_id": id, "action": verb}})
}

func cancelFlow(c *apiCtx, client, flow string) {
	if !clientIdRe.MatchString(client) || !flowIdRe.MatchString(flow) {
		apiError(c.w, 400, "invalid client or flow id")
		return
	}
	rows, ok := c.query(`SELECT cancel_flow(client_id=ClientId, flow_id=FlowId) AS R FROM scope()`,
		ordereddict.NewDict().Set("ClientId", client).Set("FlowId", flow), 1)
	if !ok {
		return
	}
	if len(rows) == 0 || utils.IsNil(firstOf(rows[0], "R")) {
		apiError(c.w, http.StatusForbidden, "The collection was not cancelled. The key may lack permission.")
		return
	}
	c.audit("api_flow_cancel", ordereddict.NewDict().Set("client_id", client).Set("flow_id", flow))
	apiWrite(c.w, 200, map[string]interface{}{"data": map[string]string{"client_id": client, "flow_id": flow, "action": "cancel"}})
}

// ------------------------------------------------------------- Clients

func getClient(c *apiCtx, client string) {
	if !clientIdRe.MatchString(client) {
		apiError(c.w, 400, "invalid client id")
		return
	}
	rows, ok := c.query(`SELECT client_id, os_info, agent_information, labels, last_seen_at, first_seen_at,
		last_ip, last_interrogate_flow_id, client_metadata(client_id=ClientId) AS metadata
		FROM clients(client_id=ClientId)`, ordereddict.NewDict().Set("ClientId", client), 1)
	if !ok {
		return
	}
	if len(rows) == 0 {
		apiError(c.w, 404, "No such client")
		return
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": rows[0]})
}

func labelClient(c *apiCtx, client string) {
	var body struct {
		Add    []string `json:"add,omitempty"`
		Remove []string `json:"remove,omitempty"`
	}
	if !clientIdRe.MatchString(client) {
		apiError(c.w, 400, "invalid client id")
		return
	}
	if !decodeBody(c, &body) {
		return
	}
	if len(body.Add)+len(body.Remove) == 0 || len(body.Add)+len(body.Remove) > 50 {
		apiError(c.w, 400, "give 1-50 labels to add or remove")
		return
	}
	for _, l := range append(append([]string{}, body.Add...), body.Remove...) {
		if !labelRe.MatchString(l) {
			apiError(c.w, 400, "invalid label "+l)
			return
		}
		// These labels aim response hunts; changing them could change
		// what an approved action runs on.
		if reservedLabels.MatchString(l) {
			apiError(c.w, http.StatusForbidden, "labels starting with response- or apitarget- are managed by Atlantiraptor")
			return
		}
	}
	for op, labels := range map[string][]string{"set": body.Add, "remove": body.Remove} {
		for _, l := range labels {
			if !c.labelClients([]string{client}, l, op) {
				apiError(c.w, http.StatusForbidden, "The label was not changed. The key may lack the label permission.")
				return
			}
		}
	}
	c.audit("api_label", ordereddict.NewDict().Set("client_id", client).Set("add", body.Add).Set("remove", body.Remove))
	getClient(c, client)
}

// ------------------------------------------------------- Uploaded files

func (c *apiCtx) flowUploads(client, flow string) ([]*ordereddict.Dict, bool) {
	if !clientIdRe.MatchString(client) || !flowIdRe.MatchString(flow) {
		apiError(c.w, 400, "invalid client or flow id")
		return nil, false
	}
	return c.query(`SELECT name, vfs_path, file_size, started FROM uploads(client_id=ClientId, flow_id=FlowId)`,
		ordereddict.NewDict().Set("ClientId", client).Set("FlowId", flow), apiMaxRows)
}

func listUploads(c *apiCtx, client, flow string) {
	rows, ok := c.flowUploads(client, flow)
	if !ok {
		return
	}
	out := []map[string]interface{}{}
	for i, r := range rows {
		out = append(out, map[string]interface{}{
			"index": i, "name": firstOf(r, "name"), "file_size": firstOf(r, "file_size"),
			"started":      firstOf(r, "started"),
			"download_url": fmt.Sprintf("/api/atl/v1/clients/%s/flows/%s/uploads/%d", client, flow, i),
		})
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": out})
}

// downloadUpload serves one file the collection uploaded. Only files
// listed for this client and flow (as the key) can be fetched.
func downloadUpload(c *apiCtx, client, flow, index string) {
	rows, ok := c.flowUploads(client, flow)
	if !ok {
		return
	}
	i, err := strconv.Atoi(index)
	if err != nil || i < 0 || i >= len(rows) {
		apiError(c.w, 404, "No such upload")
		return
	}
	size, _ := strconv.ParseInt(fmt.Sprint(firstOf(rows[i], "file_size")), 10, 64)
	if size > maxDownloadBytes {
		apiError(c.w, http.StatusRequestEntityTooLarge, "The file is larger than 100 MB; download it from the console.")
		return
	}
	if size <= 0 {
		apiError(c.w, http.StatusConflict, "The file has no recorded size; download it from the console.")
		return
	}
	// At most a few downloads at a time, each read at its real size.
	select {
	case downloadSlots <- struct{}{}:
		defer func() { <-downloadSlots }()
	default:
		w := c.w
		w.Header().Set("Retry-After", "5")
		apiError(w, http.StatusTooManyRequests, "Too many downloads in progress")
		return
	}
	data, ok := c.query(`SELECT read_file(accessor="fs", filename=Path, length=Size) AS Data FROM scope()`,
		ordereddict.NewDict().Set("Path", firstOf(rows[i], "vfs_path")).Set("Size", size), 1)
	if !ok {
		return
	}
	content := ""
	if len(data) > 0 {
		if s, isStr := firstOf(data[0], "Data").(string); isStr {
			content = s
		}
	}
	if int64(len(content)) != size {
		apiError(c.w, http.StatusBadGateway, "The file could not be read in full. The key may lack permission.")
		return
	}
	name := fmt.Sprint(firstOf(rows[i], "name"))
	base := name[strings.LastIndexAny(name, `/\`)+1:]
	c.audit("api_download", ordereddict.NewDict().Set("client_id", client).Set("flow_id", flow).Set("file", name))
	c.w.Header().Set("Content-Type", "application/octet-stream")
	c.w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, sanitizeFilename(base)))
	c.w.Header().Set("Cache-Control", "no-store")
	c.w.Header().Set("X-Content-Type-Options", "nosniff")
	c.w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	_, _ = c.w.Write([]byte(content))
}

var (
	unsafeFilenameRe = regexp.MustCompile(`[^A-Za-z0-9._ -]`)
	downloadSlots    = make(chan struct{}, 3)
)

func sanitizeFilename(s string) string {
	s = unsafeFilenameRe.ReplaceAllString(s, "_")
	if s == "" {
		return "upload.bin"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// ------------------------------------------------- Artifacts and stats

func getArtifact(c *apiCtx, name string) {
	if !artifactRe.MatchString(name) || strings.Contains(name, "/") {
		apiError(c.w, 400, "invalid artifact name")
		return
	}
	rows, ok := c.query(`SELECT name, description, type, author, parameters, required_permissions,
		precondition, sources, raw FROM artifact_definitions(names=Name)`,
		ordereddict.NewDict().Set("Name", name), 1)
	if !ok {
		return
	}
	if len(rows) == 0 {
		apiError(c.w, 404, "No such artifact")
		return
	}
	apiWrite(c.w, 200, map[string]interface{}{"data": rows[0]})
}

var (
	statsMu    sync.Mutex
	statsCache = map[string]statsEntry{}
)

type statsEntry struct {
	data    map[string]interface{}
	fetched time.Time
}

func fleetStats(c *apiCtx) {
	// Counting scans every client and hunt, so answers are reused for 15s.
	statsMu.Lock()
	if e, ok := statsCache[c.org.OrgId]; ok && time.Since(e.fetched) < 15*time.Second {
		statsMu.Unlock()
		apiWrite(c.w, 200, map[string]interface{}{"data": e.data})
		return
	}
	statsMu.Unlock()
	cutoff := time.Now().Add(-15*time.Minute).UnixNano() / 1000
	rows, ok := c.query(`SELECT count() AS Total, sum(item=if(condition=last_seen_at > Cutoff, then=1, else=0)) AS Online
		FROM clients() GROUP BY 1`, ordereddict.NewDict().Set("Cutoff", cutoff), 1)
	if !ok {
		return
	}
	hunts, ok := c.query(`SELECT count() AS Running FROM hunts() WHERE state = "RUNNING" GROUP BY 1`, ordereddict.NewDict(), 1)
	if !ok {
		return
	}
	pending, ok := c.query(`SELECT count() AS Pending FROM hunts() WHERE state = "PAUSED" AND PendingTag in tags GROUP BY 1`,
		ordereddict.NewDict().Set("PendingTag", pendingTag), 1)
	if !ok {
		return
	}
	pick := func(rs []*ordereddict.Dict, k string) interface{} {
		if len(rs) == 0 {
			return 0
		}
		return firstOf(rs[0], k)
	}
	data := map[string]interface{}{
		"clients_total": pick(rows, "Total"), "clients_online": pick(rows, "Online"),
		"hunts_running": pick(hunts, "Running"), "approvals_pending": pick(pending, "Pending"),
	}
	statsMu.Lock()
	statsCache[c.org.OrgId] = statsEntry{data: data, fetched: time.Now()}
	statsMu.Unlock()
	apiWrite(c.w, 200, map[string]interface{}{"data": data})
}

// --------------------------------------------------------------- Query

// readOnlyACL narrows a key's permissions to reading: a free-form query
// may read results and run VQL, and nothing else (no hunts, collections,
// labels, uploads or server changes), whatever roles the key holds. So
// /query can't be used to get around the approval rules of /actions.
type readOnlyACL struct {
	vql_subsystem.ACLManager
	principal string
}

// GetPrincipal keeps the key as the actor in logs. Org-scoped checks
// (CheckAccessInOrg) are not offered, so cross-org VQL is denied.
func (self *readOnlyACL) GetPrincipal() string { return self.principal }

var readOnlyPerms = []acls.ACL_PERMISSION{acls.READ_RESULTS, acls.API_QUERY}

// Restrict keeps the restriction when VQL (query()) builds a new ACL
// manager for a sub-scope, e.g. for another org or user.
func (self *readOnlyACL) Restrict(inner vql_subsystem.ACLManager) vql_subsystem.ACLManager {
	return &readOnlyACL{ACLManager: inner, principal: self.principal}
}

func newReadOnlyACL(inner vql_subsystem.ACLManager, principal string) *readOnlyACL {
	return &readOnlyACL{ACLManager: inner, principal: principal}
}

func allowedReadOnly(perms []acls.ACL_PERMISSION) bool {
	for _, p := range perms {
		ok := false
		for _, r := range readOnlyPerms {
			if p == r {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (self *readOnlyACL) CheckAccess(perms ...acls.ACL_PERMISSION) (bool, error) {
	if !allowedReadOnly(perms) {
		return false, nil
	}
	return self.ACLManager.CheckAccess(perms...)
}

func (self *readOnlyACL) CheckAccessWithArgs(perm acls.ACL_PERMISSION, args ...string) (bool, error) {
	if !allowedReadOnly([]acls.ACL_PERMISSION{perm}) {
		return false, nil
	}
	return self.ACLManager.CheckAccessWithArgs(perm, args...)
}

// runAnalysisQuery runs a caller's VQL for analysis, as the key, with
// read-only permissions (see readOnlyACL).
func runAnalysisQuery(c *apiCtx) {
	var body struct {
		Query   string            `json:"query"`
		Env     map[string]string `json:"env,omitempty"`
		MaxRows int               `json:"max_rows,omitempty"`
	}
	if !decodeBody(c, &body) {
		return
	}
	if ok, _ := services.CheckAccess(c.org, c.key.Principal(), acls.API_QUERY); !ok {
		apiError(c.w, http.StatusForbidden, "Queries need a key with the analyst role.")
		return
	}
	if strings.TrimSpace(body.Query) == "" || len(body.Query) > 64*1024 || len(body.Env) > 50 {
		apiError(c.w, 400, "query is required (at most 64 KB, 50 env values)")
		return
	}
	env := ordereddict.NewDict()
	for k, v := range body.Env {
		if !paramKeyRe.MatchString(k) || len(v) > 64*1024 {
			apiError(c.w, 400, "invalid env value "+k)
			return
		}
		env.Set(k, v)
	}
	max := body.MaxRows
	if max <= 0 || max > apiMaxRows {
		max = apiDefaultRows
	}
	rows, err := runAPIQueryWithACL(c.r.Context(), c.org,
		newReadOnlyACL(acl_managers.NewServerACLManager(c.org, c.key.Principal()), c.key.Principal()), env, body.Query, max)
	if err != nil {
		apiError(c.w, 400, "Query failed: "+oneLineText(err.Error(), 300))
		return
	}
	c.audit("api_query", ordereddict.NewDict().Set("query", oneLineText(body.Query, 2000)).Set("rows", len(rows)))
	apiWrite(c.w, 200, map[string]interface{}{"data": rows, "count": len(rows), "truncated": len(rows) >= max})
}
