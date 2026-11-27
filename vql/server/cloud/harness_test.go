package cloud

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"www.velocidex.com/golang/velociraptor/acls"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"

	_ "www.velocidex.com/golang/velociraptor/vql/common"
	_ "www.velocidex.com/golang/velociraptor/vql/functions"
	_ "www.velocidex.com/golang/velociraptor/vql/functions/functional"
	_ "www.velocidex.com/golang/velociraptor/vql/parsers"
	_ "www.velocidex.com/golang/velociraptor/vql/protocols"
)

const testPrincipal = "cloud-tester"

// testACLManager allows everything and names a principal, so secrets
// granted to that principal can be read.
type testACLManager struct{}

func (self testACLManager) CheckAccess(permission ...acls.ACL_PERMISSION) (bool, error) {
	return true, nil
}

func (self testACLManager) CheckAccessWithArgs(
	permission acls.ACL_PERMISSION, args ...string) (bool, error) {
	return true, nil
}

func (self testACLManager) GetPrincipal() string { return testPrincipal }

// Fixture times are written relative to now, e.g. "NOW-36h" or
// "NOW-90m", so the hunts' lookback windows always cover them.
var relativeTime = regexp.MustCompile(`NOW-(\d+)([hm])(Z?)`)

func expandTimes(data []byte, now time.Time) []byte {
	return relativeTime.ReplaceAllFunc(data, func(m []byte) []byte {
		parts := relativeTime.FindSubmatch(m)
		n, _ := strconv.Atoi(string(parts[1]))
		d := time.Duration(n) * time.Hour
		if string(parts[2]) == "m" {
			d = time.Duration(n) * time.Minute
		}
		t := now.Add(-d).UTC()
		// Management Activity API records carry no zone suffix.
		if string(parts[3]) == "Z" {
			return []byte(t.Format(time.RFC3339))
		}
		return []byte(t.Format("2006-01-02T15:04:05"))
	})
}

// fixtureServer serves fixtures/<dir>/<path with / replaced by __>.json
// for every GET, plus an OAuth token endpoint. Requests are recorded.
type fixtureServer struct {
	*httptest.Server
	dir      string
	now      time.Time
	requests []string
	extra    func(w http.ResponseWriter, r *http.Request) bool
}

func newFixtureServer(dir string) *fixtureServer {
	self := &fixtureServer{dir: dir, now: time.Now()}
	self.Server = httptest.NewServer(http.HandlerFunc(self.serve))
	return self
}

func (self *fixtureServer) serve(w http.ResponseWriter, r *http.Request) {
	self.requests = append(self.requests, r.Method+" "+r.URL.String())

	if strings.HasSuffix(r.URL.Path, "/token") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`)
		return
	}

	if r.Header.Get("Authorization") == "" {
		http.Error(w, "no auth", 401)
		return
	}

	if self.extra != nil && self.extra(w, r) {
		return
	}

	name := strings.ReplaceAll(strings.Trim(r.URL.Path, "/"), "/", "__")
	if strings.Contains(r.URL.RawQuery, "nonInteractiveUser") {
		name += ".noninteractive"
	}
	// The Microsoft Graph service principal itself.
	if strings.Contains(r.URL.Query().Get("$filter"), "00000003-0000-0000-c000-000000000000") {
		name += ".graph"
	}

	data, err := os.ReadFile(filepath.Join("fixtures", self.dir, name+".json"))
	if err != nil {
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"error":{"code":"ResourceNotFound","message":"no fixture %v"}}`, name)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(expandTimes(data, self.now))
}

// cloudSuite runs the Cloud.* artifacts against fixture servers.
type cloudSuite struct {
	test_utils.TestSuite
}

func (self *cloudSuite) loadArtifacts(globs ...string) {
	var paths []string
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(
			"..", "..", "..", "artifacts", "definitions", g))
		require.NoError(self.T(), err)
		paths = append(paths, matches...)
	}
	require.NotEmpty(self.T(), paths)
	sort.Strings(paths)

	// Load shared rule artifacts first so imports resolve.
	sort.SliceStable(paths, func(i, j int) bool {
		return strings.HasSuffix(paths[i], "Rules.yaml") &&
			!strings.HasSuffix(paths[j], "Rules.yaml")
	})
	self.LoadArtifactFiles(paths...)
}

func (self *cloudSuite) addSecret(type_name, name string, data *ordereddict.Dict) {
	secrets, err := services.GetSecretsService(self.ConfigObj)
	require.NoError(self.T(), err)

	scope := vql_subsystem.MakeScope()
	err = secrets.AddSecret(self.Ctx, scope, type_name, name, data, "admin")
	require.NoError(self.T(), err)

	err = secrets.ModifySecret(self.Ctx, &api_proto.ModifySecretRequest{
		TypeName: type_name, Name: name, AddUsers: []string{testPrincipal},
	}, "admin")
	require.NoError(self.T(), err)
}

// query runs VQL with the server config and returns the rows as dicts.
func (self *cloudSuite) query(vql string, env *ordereddict.Dict) []*ordereddict.Dict {
	if env == nil {
		env = ordereddict.NewDict()
	}
	manager, err := services.GetRepositoryManager(self.ConfigObj)
	require.NoError(self.T(), err)
	repository, err := manager.GetGlobalRepository(self.ConfigObj)
	require.NoError(self.T(), err)

	logging.ClearMemoryLogs()
	builder := services.ScopeBuilder{
		Config:     self.ConfigObj,
		ACLManager: testACLManager{},
		Repository: repository,
		Logger:     logging.NewPlainLogger(self.ConfigObj, &logging.FrontendComponent),
		Env:        env,
	}
	scope := manager.BuildScope(builder)
	defer scope.Close()

	statements, err := vfilter.MultiParse(vql)
	require.NoError(self.T(), err)

	var rows []*ordereddict.Dict
	for _, stmt := range statements {
		for row := range stmt.Eval(self.Ctx, scope) {
			rows = append(rows, vfilter.RowToDict(self.Ctx, scope, row))
		}
	}
	return rows
}

func (self *cloudSuite) logs() string {
	return strings.Join(logging.GetMemoryLogs(), "\n")
}

// detections summarises hunt output as "Severity|Detection|User" lines.
func detections(rows []*ordereddict.Dict) []string {
	var res []string
	for _, r := range rows {
		sev, _ := r.GetString("Severity")
		det, _ := r.GetString("Detection")
		user, _ := r.Get("User")
		res = append(res, fmt.Sprintf("%v|%v|%v", sev, det, user))
	}
	sort.Strings(res)
	return res
}

func (self *cloudSuite) assertDetections(rows []*ordereddict.Dict, expected ...string) {
	sort.Strings(expected)
	assert.Equal(self.T(), expected, detections(rows), self.logs())
}
