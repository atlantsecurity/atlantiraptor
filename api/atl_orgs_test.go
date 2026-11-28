package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/vtesting/assert"
)

type OrgsHandlerTestSuite struct {
	test_utils.TestSuite
}

func (self *OrgsHandlerTestSuite) SetupTest() {
	self.ConfigObj = self.TestSuite.LoadConfig()
	self.ConfigObj.Services.JournalService = true
	self.TestSuite.SetupTest()
	self.LoadArtifacts(`name: Server.Audit.Logs
type: SERVER_EVENT
`, `name: Server.Internal.UserManager
type: INTERNAL
`)

	self.makeUser("admin", services.ROOT_ORG_ID, "administrator")
	self.makeUser("reader", services.ROOT_ORG_ID, "reader")
}

func (self *OrgsHandlerTestSuite) makeUser(name, org_id, role string) {
	org_manager, err := services.GetOrgManager()
	assert.NoError(self.T(), err)
	err = services.GetUserManager().SetUser(self.Ctx, &api_proto.VelociraptorUser{
		Name: name, Orgs: []*api_proto.OrgRecord{{Id: org_id}},
	})
	assert.NoError(self.T(), err)
	org_config, err := org_manager.GetOrgConfig(org_id)
	assert.NoError(self.T(), err)
	assert.NoError(self.T(), services.GrantRoles(org_config, name, []string{role}))
}

func (self *OrgsHandlerTestSuite) call(user, method, query string, body interface{}) (int, map[string]interface{}) {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/atl/orgs"+query, reader)
	req = req.WithContext(context.WithValue(req.Context(), constants.GRPC_USER_CONTEXT, user))
	w := httptest.NewRecorder()
	orgsHandler().ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (self *OrgsHandlerTestSuite) orgNames() map[string]string {
	code, out := self.call("admin", http.MethodGet, "", nil)
	assert.Equal(self.T(), http.StatusOK, code)
	names := map[string]string{}
	for _, o := range out["orgs"].([]interface{}) {
		m := o.(map[string]interface{})
		names[m["id"].(string)] = m["name"].(string)
	}
	return names
}

func (self *OrgsHandlerTestSuite) TestNonAdminRefused() {
	code, _ := self.call("reader", http.MethodGet, "", nil)
	assert.Equal(self.T(), http.StatusForbidden, code)

	code, _ = self.call("reader", http.MethodPost, "", map[string]string{"action": "create", "name": "Evil"})
	assert.Equal(self.T(), http.StatusForbidden, code)

	// An administrator of a child org is not an org admin.
	org_manager, _ := services.GetOrgManager()
	_, err := org_manager.CreateNewOrg("Child", "OCHILD", services.RandomNonce)
	assert.NoError(self.T(), err)
	self.makeUser("childadmin", "OCHILD", "administrator")
	code, _ = self.call("childadmin", http.MethodPost, "", map[string]string{"action": "create", "name": "Evil"})
	assert.Equal(self.T(), http.StatusForbidden, code)
	code, _ = self.call("childadmin", http.MethodPost, "",
		map[string]string{"action": "delete", "id": "OCHILD", "confirm": "Child"})
	assert.Equal(self.T(), http.StatusForbidden, code)
}

func (self *OrgsHandlerTestSuite) TestLifecycle() {
	// Create
	code, out := self.call("admin", http.MethodPost, "", map[string]string{"action": "create", "name": "  Customer A  "})
	assert.Equal(self.T(), http.StatusOK, code, out)
	org := out["org"].(map[string]interface{})
	id := org["id"].(string)
	assert.Equal(self.T(), "Customer A", org["name"])
	assert.Equal(self.T(), "Customer A", self.orgNames()[id])

	// The creator administers the new org.
	org_manager, _ := services.GetOrgManager()
	org_config, err := org_manager.GetOrgConfig(id)
	assert.NoError(self.T(), err)
	policy, err := services.GetPolicy(org_config, "admin")
	assert.NoError(self.T(), err)
	assert.Contains(self.T(), policy.Roles, "administrator")

	// Duplicate names are refused.
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "create", "name": "customer a"})
	assert.Equal(self.T(), http.StatusConflict, code)

	// Empty and control character names are refused.
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "create", "name": "  "})
	assert.Equal(self.T(), http.StatusBadRequest, code)
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "create", "name": "a\nb"})
	assert.Equal(self.T(), http.StatusBadRequest, code)

	// Client config download carries the org's own nonce.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/atl/orgs?client_config="+id, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.GRPC_USER_CONTEXT, "admin"))
	w := httptest.NewRecorder()
	orgsHandler().ServeHTTP(w, req)
	assert.Equal(self.T(), http.StatusOK, w.Code)
	record, _ := org_manager.GetOrg(id)
	assert.True(self.T(), strings.Contains(w.Body.String(), record.Nonce))

	// Rename keeps the id and nonce, and survives a reload of the record.
	nonce := record.Nonce
	code, out = self.call("admin", http.MethodPost, "", map[string]string{"action": "rename", "id": id, "name": "Customer B"})
	assert.Equal(self.T(), http.StatusOK, code, out)
	assert.Equal(self.T(), "Customer B", self.orgNames()[id])
	record, _ = org_manager.GetOrg(id)
	assert.Equal(self.T(), nonce, record.Nonce)
	org_config, _ = org_manager.GetOrgConfig(id)
	assert.Equal(self.T(), "Customer B", org_config.OrgName)

	// Root can not be renamed or deleted.
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "rename", "id": "root", "name": "X"})
	assert.Equal(self.T(), http.StatusBadRequest, code)
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "delete", "id": "root", "confirm": "<root>"})
	assert.Equal(self.T(), http.StatusBadRequest, code)

	// Delete needs the exact name.
	code, _ = self.call("admin", http.MethodPost, "", map[string]string{"action": "delete", "id": id, "confirm": "Customer A"})
	assert.Equal(self.T(), http.StatusBadRequest, code)
	assert.Equal(self.T(), "Customer B", self.orgNames()[id])

	code, out = self.call("admin", http.MethodPost, "", map[string]string{"action": "delete", "id": id, "confirm": "Customer B"})
	assert.Equal(self.T(), http.StatusOK, code, out)
	_, present := self.orgNames()[id]
	assert.False(self.T(), present)
}

func TestOrgsHandler(t *testing.T) {
	suite.Run(t, &OrgsHandlerTestSuite{})
}
