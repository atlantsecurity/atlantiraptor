package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/utils"
	_ "www.velocidex.com/golang/velociraptor/vql_plugins"
	"www.velocidex.com/golang/velociraptor/vtesting/assert"
)

const testKillArtifact = `
name: Generic.Remediation.KillProcess
required_permissions:
  - EXECVE
parameters:
  - name: ProcessRegex
  - name: CommandLineRegex
    default: .
  - name: ReallyDoIt
    type: bool
sources:
  - query: SELECT * FROM info()
`

const testWrapperArtifact = `
name: Custom.Wrapper
sources:
  - query: SELECT * FROM Artifact.Generic.Remediation.KillProcess(ProcessRegex=".", ReallyDoIt=TRUE)
`

const testRapidArtifact = `
name: Generic.Detection.RapidHunt
parameters:
  - name: Indicator
  - name: DaysBack
  - name: IncludeEventLogs
sources:
  - query: SELECT * FROM info()
`

const testPslistArtifact = `
name: Windows.System.Pslist
sources:
  - query: SELECT * FROM info()
`

type AtlAPITestSuite struct {
	test_utils.TestSuite
	handler http.Handler
}

func (self *AtlAPITestSuite) SetupTest() {
	self.ConfigObj = self.TestSuite.LoadConfig()
	self.ConfigObj.Services.HuntDispatcher = true
	self.ConfigObj.Services.HuntManager = true
	self.TestSuite.SetupTest()
	self.LoadArtifacts(testKillArtifact, testPslistArtifact, testWrapperArtifact, testRapidArtifact)
	self.CreateClient("C.0123456789abcdef")
	self.CreateClient("C.fedcba9876543210")
	self.handler = AtlAPIHandler(self.ConfigObj)
	apiKeyCache = nil
}

func (self *AtlAPITestSuite) keyBy(creator string, roles ...string) string {
	_, token, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, creator, creator+" "+strings.Join(roles, " "), roles, 0)
	assert.NoError(self.T(), err)
	return token
}

func (self *AtlAPITestSuite) key(roles ...string) string {
	_, token, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, "admin", "test "+strings.Join(roles, " "), roles, 0)
	assert.NoError(self.T(), err)
	return token
}

func (self *AtlAPITestSuite) call(method, path, token string, body interface{}) (int, map[string]interface{}) {
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/atl/v1/"+path, reader).WithContext(self.Ctx)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	self.handler.ServeHTTP(rec, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (self *AtlAPITestSuite) TestAuth() {
	code, _ := self.call("GET", "whoami", "", nil)
	assert.Equal(self.T(), 401, code)
	code, _ = self.call("GET", "whoami", "atl_0123456789abcdef_nope", nil)
	assert.Equal(self.T(), 401, code)

	token := self.key("reader")
	code, out := self.call("GET", "whoami", token, nil)
	assert.Equal(self.T(), 200, code)
	assert.True(self.T(), strings.HasPrefix(utils.ToString(out["principal"]), "api-"))

	// A wrong secret for a real id is refused.
	code, _ = self.call("GET", "whoami", token[:len(token)-2]+"xx", nil)
	assert.Equal(self.T(), 401, code)

	// Failures from the same address never lock out a valid key.
	for i := 0; i < authFailBurst+5; i++ {
		self.call("GET", "whoami", "atl_0123456789abcdef_nope", nil)
	}
	code, _ = self.call("GET", "whoami", "atl_0123456789abcdef_nope", nil)
	assert.Equal(self.T(), 429, code)
	code, _ = self.call("GET", "whoami", token, nil)
	assert.Equal(self.T(), 200, code)

	// Revoked keys stop working.
	authFailMu.Lock()
	authFails = map[string]*bucket{}
	authFailMu.Unlock()
	keys, _ := ListAPIKeys(self.ConfigObj)
	_, err := RevokeAPIKey(self.ConfigObj, keys[0].ID)
	assert.NoError(self.T(), err)
	code, _ = self.call("GET", "whoami", token, nil)
	assert.Equal(self.T(), 401, code)
}

func (self *AtlAPITestSuite) TestCatalogueAndReads() {
	token := self.key("reader")
	code, out := self.call("GET", "actions", token, nil)
	assert.Equal(self.T(), 200, code)
	assert.True(self.T(), len(out["data"].([]interface{})) > 5)

	code, _ = self.call("GET", "clients", token, nil)
	assert.Equal(self.T(), 200, code)
	code, out = self.call("GET", "alerts?since=1", token, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	code, _ = self.call("GET", "nope", token, nil)
	assert.Equal(self.T(), 404, code)
}

func (self *AtlAPITestSuite) TestPermissions() {
	reader := self.key("reader")
	code, _ := self.call("POST", "collections", reader, map[string]interface{}{
		"client_id": "C.0123456789abcdef", "artifacts": []string{"Windows.System.Pslist"}})
	assert.Equal(self.T(), 403, code)

	// Hunters may collect, but not run response artifacts.
	hunter := self.key("hunter")
	code, out := self.call("POST", "collections", hunter, map[string]interface{}{
		"client_id": "C.0123456789abcdef", "artifacts": []string{"Windows.System.Pslist"}})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))

	code, out = self.call("POST", "actions/kill/run", hunter, map[string]interface{}{
		"target": map[string]string{"client_id": "C.0123456789abcdef"}, "parameters": map[string]string{"ProcessRegex": "evil"}})
	assert.Equal(self.T(), 403, code, fmt.Sprint(out))
}

func (self *AtlAPITestSuite) TestResponseAction() {
	responder := self.key("responder")
	target := map[string]string{"client_id": "C.0123456789abcdef"}

	// Missing required parameter.
	code, _ := self.call("POST", "actions/kill/run", responder, map[string]interface{}{"target": target})
	assert.Equal(self.T(), 400, code)
	// Unknown parameter.
	code, _ = self.call("POST", "actions/kill/run", responder, map[string]interface{}{"target": target,
		"parameters": map[string]string{"ProcessRegex": "x", "ReallyDoIt": "Y"}})
	assert.Equal(self.T(), 400, code)

	// Dry run by default.
	code, out := self.call("POST", "actions/kill/run", responder, map[string]interface{}{"target": target,
		"parameters": map[string]string{"ProcessRegex": "evil"}})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	assert.Equal(self.T(), true, out["data"].(map[string]interface{})["dry_run"])

	// Live needs a reason.
	live := map[string]interface{}{"target": target, "dry_run": false,
		"parameters": map[string]string{"ProcessRegex": "evil"}}
	code, _ = self.call("POST", "actions/kill/run", responder, live)
	assert.Equal(self.T(), 400, code)

	// With approval required, a live action waits as a paused hunt.
	_, err := runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj), ordereddict.NewDict(),
		`SELECT server_set_metadata(atl_response_require_approval="Y") FROM scope()`, 1)
	assert.NoError(self.T(), err)
	live["reason"] = "ticket 42"
	code, out = self.call("POST", "actions/kill/run", responder, live)
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	data := out["data"].(map[string]interface{})
	assert.Equal(self.T(), "waiting_for_approval", data["state"])

	code, out = self.call("GET", "hunts/"+utils.ToString(data["hunt_id"]), responder, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	hunt := out["data"].(map[string]interface{})
	assert.Equal(self.T(), "PAUSED", utils.ToString(hunt["state"]))
	tags, _ := json.Marshal(hunt["tags"])
	assert.True(self.T(), strings.Contains(string(tags), "approval:pending"), string(tags))

	// The request carries the console's request record and a one-off label.
	rows, err := runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj),
		ordereddict.NewDict().Set("H", data["hunt_id"]),
		`SELECT start_request.user_data AS U, condition AS C FROM hunts(hunt_id=H)`, 1)
	assert.NoError(self.T(), err)
	assert.Equal(self.T(), 1, len(rows))
	u, _ := rows[0].Get("U")
	assert.True(self.T(), strings.Contains(utils.ToString(u), `"reason":"ticket 42"`), utils.ToString(u))
	assert.True(self.T(), strings.Contains(utils.ToString(u), `"key_owner":"admin"`), utils.ToString(u))
	cv, _ := rows[0].Get("C")
	cond, _ := json.Marshal(cv)
	assert.True(self.T(), strings.Contains(string(cond), `"response-`), string(cond))
}

func (self *AtlAPITestSuite) TestGenericEndpointsRefuseResponseArtifacts() {
	responder := self.key("responder")
	kill := map[string]interface{}{"artifacts": []string{"Generic.Remediation.KillProcess"},
		"parameters": map[string]interface{}{"Generic.Remediation.KillProcess": map[string]string{"ProcessRegex": ".", "ReallyDoIt": "Y"}}}
	kill["target"] = map[string]bool{"all": true}
	code, out := self.call("POST", "hunts", responder, kill)
	assert.Equal(self.T(), 403, code, fmt.Sprint(out))

	code, out = self.call("POST", "collections", responder, map[string]interface{}{
		"client_id": "C.0123456789abcdef", "artifacts": []string{"Generic.Remediation.KillProcess/Source"}})
	assert.Equal(self.T(), 403, code, fmt.Sprint(out))

	// A wrapper that calls a response artifact is refused too.
	code, out = self.call("POST", "collections", responder, map[string]interface{}{
		"client_id": "C.0123456789abcdef", "artifacts": []string{"Custom.Wrapper"}})
	assert.Equal(self.T(), 403, code, fmt.Sprint(out))

	code, out = self.call("POST", "ioc-sweeps", responder, map[string]interface{}{
		"target": map[string]bool{"all": true}, "indicators": []map[string]string{{"type": "domain", "value": "a|.*"}}})
	assert.Equal(self.T(), 400, code, fmt.Sprint(out))
}

func (self *AtlAPITestSuite) TestClientList() {
	responder := self.key("responder")
	two := []string{"C.0123456789abcdef", "C.fedcba9876543210"}

	// Several clients, dry run: one hunt aimed at a fresh label on both.
	code, out := self.call("POST", "actions/kill/run", responder, map[string]interface{}{
		"target": map[string]interface{}{"client_ids": two}, "parameters": map[string]string{"ProcessRegex": "evil"}})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	data := out["data"].(map[string]interface{})
	rows, err := runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj),
		ordereddict.NewDict().Set("H", data["hunt_id"]),
		`SELECT start_request.user_data AS U, condition.labels.label AS L FROM hunts(hunt_id=H)`, 1)
	assert.NoError(self.T(), err)
	u, _ := rows[0].Get("U")
	assert.True(self.T(), strings.Contains(utils.ToString(u), `"one_off_clients":["C.0123456789abcdef","C.fedcba9876543210"]`), utils.ToString(u))
	l, _ := rows[0].Get("L")
	label := strings.Trim(utils.ToString(l), `[]" `)
	assert.True(self.T(), strings.HasPrefix(label, "response-"), label)
	for _, id := range two {
		rows, _ := runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj),
			ordereddict.NewDict().Set("C", id), `SELECT labels FROM clients(client_id=C)`, 1)
		v, _ := rows[0].Get("labels")
		assert.True(self.T(), strings.Contains(fmt.Sprint(v), label), fmt.Sprint(v))
	}

	// Mixed target modes and oversized lists are refused.
	code, _ = self.call("POST", "actions/kill/run", responder, map[string]interface{}{
		"target": map[string]interface{}{"client_ids": two, "all": true}, "parameters": map[string]string{"ProcessRegex": "x"}})
	assert.Equal(self.T(), 400, code)
	many := []string{}
	for i := 0; i < maxTargetClients+1; i++ {
		many = append(many, fmt.Sprintf("C.%016x", i))
	}
	code, _ = self.call("POST", "actions/kill/run", responder, map[string]interface{}{
		"target": map[string]interface{}{"client_ids": many}, "parameters": map[string]string{"ProcessRegex": "x"}})
	assert.Equal(self.T(), 400, code)
}

func (self *AtlAPITestSuite) TestRapidHunt() {
	hunter := self.key("hunter")
	code, _ := self.call("POST", "rapid-hunts", hunter, map[string]interface{}{"indicator": "a|.*"})
	assert.Equal(self.T(), 400, code)
	code, out := self.call("POST", "rapid-hunts", hunter, map[string]interface{}{"indicator": "https://evil.example/x", "days_back": 7})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	id := utils.ToString(out["data"].(map[string]interface{})["hunt_id"])

	code, out = self.call("GET", "rapid-hunts/"+id, hunter, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	data := out["data"].(map[string]interface{})
	assert.Equal(self.T(), "https://evil.example/x", data["indicator"])

	code, out = self.call("GET", "rapid-hunts", hunter, nil)
	assert.Equal(self.T(), 200, code)
	assert.True(self.T(), strings.Contains(fmt.Sprint(out["data"]), id))

	// A normal hunt is not a rapid hunt.
	code, _ = self.call("GET", "rapid-hunts/H.NOTRAPID1", hunter, nil)
	assert.Equal(self.T(), 404, code)
}

func (self *AtlAPITestSuite) TestApprovals() {
	_, err := runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj), ordereddict.NewDict(),
		`SELECT server_set_metadata(atl_response_require_approval="Y") FROM scope()`, 1)
	assert.NoError(self.T(), err)
	requester := self.keyBy("alice", "responder")
	code, out := self.call("POST", "actions/kill/run", requester, map[string]interface{}{
		"target": map[string]string{"client_id": "C.0123456789abcdef"}, "dry_run": false, "reason": "INC-7",
		"parameters": map[string]string{"ProcessRegex": "evil"}})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	id := utils.ToString(out["data"].(map[string]interface{})["hunt_id"])

	code, out = self.call("GET", "approvals", requester, nil)
	assert.Equal(self.T(), 200, code)
	assert.True(self.T(), strings.Contains(fmt.Sprint(out["data"]), id))

	// Starting it directly is refused.
	code, _ = self.call("POST", "hunts/"+id+"/start", requester, nil)
	assert.Equal(self.T(), 409, code)

	// The requesting key, and another key of the same person, can't approve.
	code, dbg0 := self.call("POST", "approvals/"+id+"/approve", requester, nil)
	assert.Equal(self.T(), 403, code, fmt.Sprint(dbg0))
	code, dbg := self.call("POST", "approvals/"+id+"/approve", self.keyBy("alice", "hunter"), nil)
	assert.Equal(self.T(), 403, code, fmt.Sprint(dbg))
	// A reader key can't decide.
	code, _ = self.call("POST", "approvals/"+id+"/approve", self.keyBy("bob", "reader"), nil)
	assert.Equal(self.T(), 403, code)

	// Someone else who can't run the action themselves (a hunter can't kill) can't approve it.
	code, out = self.call("POST", "approvals/"+id+"/approve", self.keyBy("bob", "hunter"), nil)
	assert.Equal(self.T(), 403, code, fmt.Sprint(out))
	// hunt_update through the API (start) is refused while pending.
	code, _ = self.call("POST", "hunts/"+id+"/start", self.keyBy("bob", "responder"), nil)
	assert.Equal(self.T(), 409, code)

	// Another responder can.
	code, out = self.call("POST", "approvals/"+id+"/approve", self.keyBy("bob", "responder"), nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	code, out = self.call("GET", "hunts/"+id, requester, nil)
	assert.Equal(self.T(), "RUNNING", utils.ToString(out["data"].(map[string]interface{})["state"]))
	// Decided requests can't be decided again.
	code, _ = self.call("POST", "approvals/"+id+"/reject", self.keyBy("carol", "hunter"), nil)
	assert.Equal(self.T(), 409, code)

	// A rejected request can never be started again, by any path.
	code, out = self.call("POST", "actions/kill/run", requester, map[string]interface{}{
		"target": map[string]bool{"all": true}, "dry_run": false, "reason": "INC-8",
		"parameters": map[string]string{"ProcessRegex": "evil"}})
	assert.Equal(self.T(), 201, code, fmt.Sprint(out))
	id2 := utils.ToString(out["data"].(map[string]interface{})["hunt_id"])
	code, out = self.call("POST", "approvals/"+id2+"/reject", self.keyBy("dave", "responder"), nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	code, _ = self.call("POST", "hunts/"+id2+"/start", requester, nil)
	assert.Equal(self.T(), 403, code)
	_, err = runAPIQuery(self.Ctx, self.ConfigObj, utils.GetSuperuserName(self.ConfigObj),
		ordereddict.NewDict().Set("H", id2), `SELECT hunt_update(hunt_id=H, start=TRUE) FROM scope()`, 1)
	assert.NoError(self.T(), err)
	code, out = self.call("GET", "hunts/"+id2, requester, nil)
	assert.Equal(self.T(), "STOPPED", utils.ToString(out["data"].(map[string]interface{})["state"]))
}

func (self *AtlAPITestSuite) TestClientsLabelsQueryStats() {
	hunter := self.key("hunter")
	code, out := self.call("GET", "clients/C.0123456789abcdef", hunter, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	code, _ = self.call("POST", "clients/C.0123456789abcdef/labels", hunter, map[string]interface{}{"add": []string{"response-abcdef0123456789"}})
	assert.Equal(self.T(), 403, code)
	code, out = self.call("POST", "clients/C.0123456789abcdef/labels", hunter, map[string]interface{}{"add": []string{"siem-flagged"}})
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	assert.True(self.T(), strings.Contains(fmt.Sprint(out["data"]), "siem-flagged"))

	code, _ = self.call("POST", "query", self.key("reader"), map[string]interface{}{"query": "SELECT 1 AS X FROM scope()"})
	assert.Equal(self.T(), 403, code)
	// Any key with the analyst role may query; queries are read-only.
	code, _ = self.call("POST", "query", self.key("responder", "analyst"), map[string]interface{}{"query": "SELECT 1 AS X FROM scope()"})
	assert.Equal(self.T(), 200, code)
	code, out = self.call("POST", "query", self.key("analyst"), map[string]interface{}{"query": "SELECT 1 AS X FROM scope()"})
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	// Queries are read-only even for keys that may label clients.
	code, _ = self.call("POST", "query", self.key("analyst"), map[string]interface{}{
		"query": `SELECT label(client_id="C.0123456789abcdef", labels=["response-abcdef0123456789"], op="set") AS L FROM scope()`})
	assert.Equal(self.T(), 200, code)
	code, out = self.call("GET", "clients/C.0123456789abcdef", hunter, nil)
	assert.False(self.T(), strings.Contains(fmt.Sprint(out["data"]), "response-abcdef0123456789"))
	// Reserved labels can't be used as targets.
	code, _ = self.call("POST", "hunts", hunter, map[string]interface{}{
		"artifacts": []string{"Windows.System.Pslist"}, "target": map[string]interface{}{"labels": []string{"Response-abc"}}})
	assert.Equal(self.T(), 400, code)

	code, out = self.call("GET", "stats", hunter, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
	code, out = self.call("GET", "artifacts/Windows.System.Pslist", hunter, nil)
	assert.Equal(self.T(), 200, code, fmt.Sprint(out))
}

func TestAtlAPI(t *testing.T) {
	suite.Run(t, &AtlAPITestSuite{})
}
