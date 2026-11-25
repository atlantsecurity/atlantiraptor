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
	self.LoadArtifacts(testKillArtifact, testPslistArtifact)
	self.CreateClient("C.0123456789abcdef")
	self.handler = AtlAPIHandler(self.ConfigObj)
	apiKeyCache = nil
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

	// Revoked keys stop working.
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

	code, out = self.call("POST", "ioc-sweeps", responder, map[string]interface{}{
		"target": map[string]bool{"all": true}, "indicators": []map[string]string{{"type": "domain", "value": "a|.*"}}})
	assert.Equal(self.T(), 400, code, fmt.Sprint(out))
}

func TestAtlAPI(t *testing.T) {
	suite.Run(t, &AtlAPITestSuite{})
}
