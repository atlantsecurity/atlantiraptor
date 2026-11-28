package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	actions_proto "www.velocidex.com/golang/velociraptor/actions/proto"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/vtesting/assert"
)

type FleetHandlerTestSuite struct {
	test_utils.TestSuite
}

func (self *FleetHandlerTestSuite) SetupTest() {
	self.ConfigObj = self.TestSuite.LoadConfig()
	self.TestSuite.SetupTest()

	for name, role := range map[string]string{"analyst": "reader", "nobody": ""} {
		err := services.GetUserManager().SetUser(self.Ctx, &api_proto.VelociraptorUser{
			Name: name, Orgs: []*api_proto.OrgRecord{{Id: services.ROOT_ORG_ID}},
		})
		assert.NoError(self.T(), err)
		if role != "" {
			assert.NoError(self.T(), services.GrantRoles(self.ConfigObj, name, []string{role}))
		}
	}

	client_info_manager, err := services.GetClientInfoManager(self.ConfigObj)
	assert.NoError(self.T(), err)
	now := time.Now()
	for _, c := range []struct {
		id, os, version string
		ago             time.Duration
	}{
		{"C.1111111111111111", "windows", "1.0.6", time.Minute},
		{"C.2222222222222222", "windows", "1.0.5", 40 * 24 * time.Hour},
		{"C.3333333333333333", "linux", "1.0.6", 10 * 24 * time.Hour},
	} {
		err := client_info_manager.Set(self.Ctx, &services.ClientInfo{ClientInfo: &actions_proto.ClientInfo{
			ClientId: c.id, Hostname: "h" + c.id[2:5], System: c.os, ClientVersion: c.version,
			Ping: uint64(now.Add(-c.ago).UnixNano() / 1000),
		}})
		assert.NoError(self.T(), err)
	}
}

func (self *FleetHandlerTestSuite) call(user, query string) (int, map[string]interface{}) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/atl/fleet"+query, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.GRPC_USER_CONTEXT, user))
	w := httptest.NewRecorder()
	fleetHandler().ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (self *FleetHandlerTestSuite) TestSummary() {
	code, out := self.call("analyst", "")
	assert.Equal(self.T(), http.StatusOK, code)
	assert.Equal(self.T(), float64(3), out["total"])
	assert.Equal(self.T(), float64(1), out["online"])
	assert.Equal(self.T(), float64(1), out["quiet_7_count"])
	assert.Equal(self.T(), float64(1), out["quiet_30_count"])
}

func (self *FleetHandlerTestSuite) TestOutdatedIds() {
	code, out := self.call("analyst", "?os=windows&versions=1.0.5")
	assert.Equal(self.T(), http.StatusOK, code)
	assert.Equal(self.T(), []interface{}{"C.2222222222222222"}, out["client_ids"])
}

func (self *FleetHandlerTestSuite) TestNoPermission() {
	code, _ := self.call("nobody", "")
	assert.Equal(self.T(), http.StatusForbidden, code)
}

func TestFleetHandler(t *testing.T) {
	suite.Run(t, &FleetHandlerTestSuite{})
}
