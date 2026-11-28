package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/services"
)

type BackendTestSuite struct {
	test_utils.TestSuite
}

func (self *BackendTestSuite) SetupTest() {
	self.TestSuite.SetupTest()
	self.LoadArtifactFiles(
		"../../artifacts/definitions/Generic/Utils/FetchBinary.yaml",
		"../../artifacts/definitions/Admin/Client/Upgrade/Atlantiraptor.yaml")
}

// The real backend hosts the binary as a tool and sends the upgrade
// artifact with the tool's hash and the target version.
func (self *BackendTestSuite) TestPublishAndSchedule() {
	t := self.T()
	dir := t.TempDir()
	body := []byte("pretend this is the signed 1.0.4 agent")
	sum := sha256.Sum256(body)
	path := filepath.Join(dir, "agent.exe")
	require.NoError(t, os.WriteFile(path, body, 0600))
	bin := &BinaryInfo{Version: "1.0.4", SHA256: hex.EncodeToString(sum[:]), path: path}

	b := &serverBackend{config_obj: self.ConfigObj, cache_dir: dir}
	require.NoError(t, b.PublishTool(self.Ctx, bin))

	inventory, err := services.GetInventory(self.ConfigObj)
	require.NoError(t, err)
	tool, err := inventory.ProbeToolInfo(self.Ctx, self.ConfigObj, ToolName, "")
	require.NoError(t, err)
	assert.Equal(t, bin.SHA256, tool.Hash)
	assert.True(t, tool.ServeLocally)
	assert.NotEmpty(t, tool.ServeUrl)

	// Publishing the same binary again is a no-op.
	require.NoError(t, b.PublishTool(self.Ctx, bin))

	self.CreateClient("C.1234")
	clients, err := b.ListClients(self.Ctx, DefaultExcludeLabel)
	require.NoError(t, err)
	found := false
	for _, c := range clients {
		if c.ClientId == "C.1234" {
			found = true
		}
	}
	assert.True(t, found, "client not listed: %v", clients)

	flow_id, err := b.Schedule(self.Ctx, "root", "C.1234", "1.0.4")
	require.NoError(t, err)
	assert.NotEmpty(t, flow_id)

	client_info_manager, err := services.GetClientInfoManager(self.ConfigObj)
	require.NoError(t, err)
	tasks, err := client_info_manager.PeekClientTasks(self.Ctx, "C.1234")
	require.NoError(t, err)

	env := map[string]string{}
	for _, task := range tasks {
		if task.FlowRequest == nil {
			continue
		}
		for _, action := range task.FlowRequest.VQLClientActions {
			for _, e := range action.Env {
				env[e.Key] = e.Value
			}
		}
	}
	assert.Equal(t, "1.0.4", env["TargetVersion"])
	assert.Equal(t, bin.SHA256, env["Tool_"+ToolName+"_HASH"])
	assert.NotEmpty(t, env["Tool_"+ToolName+"_URL"])

	r := b.FlowResult(self.Ctx, "root", "C.1234", flow_id)
	assert.NotEqual(t, "missing", r.State)
	assert.Equal(t, "missing", b.FlowResult(self.Ctx, "root", "C.1234", "F.NOPE").State)
}

func TestBackend(t *testing.T) {
	suite.Run(t, &BackendTestSuite{})
}
