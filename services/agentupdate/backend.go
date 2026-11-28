package agentupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	actions_proto "www.velocidex.com/golang/velociraptor/actions/proto"
	artifacts_proto "www.velocidex.com/golang/velociraptor/artifacts/proto"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	flows_proto "www.velocidex.com/golang/velociraptor/flows/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql/acl_managers"
)

const creator = "AgentUpdateService"

// The test suite replaces these.
var (
	downloadReleaseAsset = selfupdate.DownloadReleaseAsset
	verifySigner         = verifyAgentBinary
)

// verifyAgentBinary requires Atlant Security's signature. A Windows
// server also has Windows check the signature and certificate chain;
// other servers can only read the names, and every agent runs the full
// check itself before installing.
func verifyAgentBinary(path string) (string, error) {
	if selfupdate.TrustSupported {
		return selfupdate.VerifyBinary(path)
	}
	return selfupdate.VerifySignerNames(path)
}

func binaryCachePath(dir, version string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "Atlantiraptor-windows-amd64-"+version+".exe")
}

type serverBackend struct {
	config_obj *config_proto.Config
	cache_dir  string

	mu sync.Mutex
	// org id -> hash of the tool published there.
	published map[string]string
}

func fileSHA256(path string) (string, int64, error) {
	fd, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer fd.Close()
	h := sha256.New()
	n, err := io.Copy(h, fd)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// PrepareBinary returns the checked Windows binary of version: from the
// cache if it is still intact, else from the GitHub release (checked
// against its SHA256SUMS), else, on a Windows server running exactly
// that release, this server's own binary.
func (self *serverBackend) PrepareBinary(ctx context.Context, version string,
	cached *BinaryInfo) (*BinaryInfo, error) {
	if self.cache_dir == "" {
		return nil, errors.New("the server has no datastore folder to keep the agent in")
	}
	path := binaryCachePath(self.cache_dir, version)

	if cached != nil && cached.Version == version {
		sum, _, err := fileSHA256(path)
		if err == nil && sum == cached.SHA256 {
			cached.path = path
			return cached, nil
		}
	}

	if err := os.MkdirAll(self.cache_dir, 0700); err != nil {
		return nil, err
	}

	source := "GitHub release v" + version
	tmp := path + ".download"
	_, err := downloadReleaseAsset(ctx, version, WindowsAsset, tmp)
	if err != nil {
		own, own_err := self.ownBinary(version)
		if own_err != nil {
			return nil, err
		}
		_ = os.Remove(tmp)
		if cerr := copyFile(own, tmp); cerr != nil {
			return nil, fmt.Errorf("%v; copying this server's binary: %w", err, cerr)
		}
		source = "this server's own binary (GitHub: " + err.Error() + ")"
	}

	subject, err := verifySigner(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("the %v agent failed the signature check: %w", version, err)
	}
	sum, size, err := fileSHA256(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	self.cleanCache(path)

	return &BinaryInfo{
		Version:  version,
		SHA256:   sum,
		Size:     size,
		Signer:   subject,
		Source:   source,
		Prepared: time.Now().Unix(),
		path:     path,
	}, nil
}

// ownBinary is this server's executable if it is the Windows release
// build of version (the agent and server are one binary).
func (self *serverBackend) ownBinary(version string) (string, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" ||
		config.ReleaseVersion() != version {
		return "", errors.New("this server is not that Windows release")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// cleanCache removes agent binaries of other versions.
func (self *serverBackend) cleanCache(keep string) {
	entries, err := os.ReadDir(self.cache_dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(self.cache_dir, e.Name())
		if p != keep && strings.HasPrefix(e.Name(), "Atlantiraptor-windows-amd64-") {
			_ = os.Remove(p)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (self *serverBackend) orgConfigs() ([]*config_proto.Config, error) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, err
	}
	var result []*config_proto.Config
	for _, rec := range org_manager.ListOrgs() {
		if rec.Redirected {
			continue
		}
		org_config, err := org_manager.GetOrgConfig(rec.Id)
		if err != nil {
			continue
		}
		result = append(result, org_config)
	}
	return result, nil
}

// PublishTool hosts the binary as the AtlantiraptorAgentWindows tool in
// every org, so agents download it from this server.
func (self *serverBackend) PublishTool(ctx context.Context, bin *BinaryInfo) error {
	orgs, err := self.orgConfigs()
	if err != nil {
		return err
	}
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.published == nil {
		self.published = make(map[string]string)
	}
	var errs []string
	for _, org_config := range orgs {
		if self.published[org_config.OrgId] == bin.SHA256 {
			continue
		}
		if err := publishToOrg(ctx, org_config, bin); err != nil {
			errs = append(errs, fmt.Sprintf("org %v: %v", org_config.OrgId, err))
			continue
		}
		self.published[org_config.OrgId] = bin.SHA256
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func publishToOrg(ctx context.Context, org_config *config_proto.Config, bin *BinaryInfo) error {
	inventory, err := services.GetInventory(org_config)
	if err != nil {
		return err
	}
	existing, err := inventory.ProbeToolInfo(ctx, org_config, ToolName, "")
	if err == nil && existing.Hash == bin.SHA256 && existing.ServeLocally {
		return nil
	}

	tool := &artifacts_proto.Tool{
		Name:         ToolName,
		Filename:     "Atlantiraptor-" + bin.Version + ".exe",
		ServeLocally: true,
		ExpectedHash: bin.SHA256,
	}
	err = inventory.AddTool(ctx, org_config, tool, services.ToolOptions{AdminOverride: true})
	if err != nil {
		return err
	}
	writer, err := inventory.WriteTool(ctx, org_config, ToolName, "")
	if err != nil {
		return err
	}
	fd, err := os.Open(bin.path)
	if err != nil {
		writer.Close()
		return err
	}
	_, err = utils.Copy(ctx, writer, fd)
	fd.Close()
	cerr := writer.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	got, err := inventory.GetToolInfo(ctx, org_config, ToolName, "")
	if err != nil {
		return err
	}
	if got.Hash != bin.SHA256 {
		return fmt.Errorf("the hosted tool has hash %v, expected %v", got.Hash, bin.SHA256)
	}
	return nil
}

func (self *serverBackend) ListClients(ctx context.Context, exclude_label string) ([]clientView, error) {
	orgs, err := self.orgConfigs()
	if err != nil {
		return nil, err
	}
	var result []clientView
	for _, org_config := range orgs {
		client_info_manager, err := services.GetClientInfoManager(org_config)
		if err != nil {
			continue
		}
		labeler := services.GetLabeler(org_config)
		for client_id := range client_info_manager.ListClients(ctx) {
			info, err := client_info_manager.Get(ctx, client_id)
			if err != nil || info == nil || info.ClientInfo == nil {
				continue
			}
			c := clientView{
				OrgId:    org_config.OrgId,
				ClientId: client_id,
				Hostname: info.Hostname,
				OS:       info.System,
				Name:     info.ClientName,
				Version:  info.ClientVersion,
				LastSeen: time.Unix(0, int64(info.Ping)*1000),
			}
			if exclude_label != "" && labeler != nil {
				c.Excluded = labeler.IsLabelSet(ctx, org_config, client_id, exclude_label)
			}
			result = append(result, c)
		}
	}
	return result, nil
}

func (self *serverBackend) orgConfig(org_id string) (*config_proto.Config, error) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, err
	}
	return org_manager.GetOrgConfig(org_id)
}

func (self *serverBackend) FlowResult(ctx context.Context, org_id, client_id, flow_id string) flowResult {
	org_config, err := self.orgConfig(org_id)
	if err != nil || flow_id == "" {
		return flowResult{State: "missing"}
	}
	launcher, err := services.GetLauncher(org_config)
	if err != nil {
		return flowResult{State: "running"}
	}
	details, err := launcher.GetFlowDetails(ctx, org_config, services.GetFlowOptions{},
		client_id, flow_id)
	if err != nil || details == nil || details.Context == nil {
		return flowResult{State: "missing"}
	}
	switch details.Context.State {
	case flows_proto.ArtifactCollectorContext_ERROR:
		return flowResult{State: "error", Status: details.Context.Status}
	case flows_proto.ArtifactCollectorContext_FINISHED:
		return flowResult{State: "finished"}
	}
	return flowResult{State: "running"}
}

func (self *serverBackend) Schedule(ctx context.Context, org_id, client_id, target string) (string, error) {
	org_config, err := self.orgConfig(org_id)
	if err != nil {
		return "", err
	}
	launcher, err := services.GetLauncher(org_config)
	if err != nil {
		return "", err
	}
	manager, err := services.GetRepositoryManager(org_config)
	if err != nil {
		return "", err
	}
	repository, err := manager.GetGlobalRepository(org_config)
	if err != nil {
		return "", err
	}
	return launcher.ScheduleArtifactCollection(ctx, org_config,
		acl_managers.NullACLManager{}, repository,
		&flows_proto.ArtifactCollectorArgs{
			Creator:   creator,
			ClientId:  client_id,
			Artifacts: []string{ArtifactName},
			Specs: []*flows_proto.ArtifactSpec{{
				Artifact: ArtifactName,
				Parameters: &flows_proto.ArtifactParameters{
					Env: []*actions_proto.VQLEnv{{Key: "TargetVersion", Value: target}},
				},
			}},
			// Up to 5 minutes of random delay, then a large download.
			Timeout: 3600,
		}, func() {
			notifier, err := services.GetNotifier(org_config)
			if err == nil {
				_ = notifier.NotifyListener(ctx, org_config, client_id, "AgentUpdate")
			}
		})
}

func (self *serverBackend) Audit(ctx context.Context, principal, operation string,
	details map[string]interface{}) {
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d := ordereddict.NewDict()
	for _, k := range keys {
		d.Set(k, details[k])
	}
	if err := services.LogAudit(ctx, self.config_obj, principal, operation, d); err != nil {
		logging.GetLogger(self.config_obj, &logging.FrontendComponent).
			Error("agent update audit %v: %v", operation, err)
	}
}
