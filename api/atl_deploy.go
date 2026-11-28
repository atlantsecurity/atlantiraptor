package api

// GET /api/v1/atl/deploy: everything needed to install agents that
// connect to this server (console page Clients > Deploy a client).
// Server administrators of the org only, because the client
// configuration lets anyone who has it enroll a computer.
//
//	GET                          the org's deployment info and install commands (JSON)
//	GET ?file=client.config.yaml the client configuration
//	GET ?file=<script>           an install script with the configuration inside
//	GET ?file=Atlantiraptor-Intune.intunewin
//	                             an Intune Win32 app package of the Windows script
//
// Nothing here creates keys: the client configuration (server URLs,
// CA certificate and the org's nonce) is the one made when the server
// or org was created, the same as `config client` and the MSI use.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/yaml/v2"
	"google.golang.org/protobuf/proto"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/agentmtls"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/utils/intunewin"
)

//go:embed deploy_templates/*
var deployTemplates embed.FS

const (
	deployConfigFile   = "client.config.yaml"
	deployWindowsFile  = "Install-Atlantiraptor.ps1"
	deployDetectFile   = "Detect-Atlantiraptor.ps1"
	deployLinuxFile    = "install-atlantiraptor-linux.sh"
	deployMacFile      = "install-atlantiraptor-macos.sh"
	deployIntuneFile   = "Atlantiraptor-Intune.intunewin"
	deployWindowsAsset = "Atlantiraptor-windows-amd64.exe"

	// Where the MSI (scripts/build-msi.ps1) and the Windows install
	// script put the agent.
	deployWindowsBase = `$ProgramFiles\Atlant Security\Atlantiraptor`
)

var deployVersionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type deployCommands struct {
	Windows string `json:"windows"`
	Linux   string `json:"linux"`
	MacOS   string `json:"macos"`
}

type deployIntune struct {
	InstallCommand   string `json:"install_command"`
	UninstallCommand string `json:"uninstall_command"`
	SetupFile        string `json:"setup_file"`
}

type deployInfo struct {
	OrgId      string   `json:"org_id"`
	OrgName    string   `json:"org_name"`
	ServerURLs []string `json:"server_urls"`
	// Every server URL is on this computer only (for example the
	// `gui` lab mode): agents elsewhere cannot connect.
	LocalOnly      bool           `json:"local_only"`
	Version        string         `json:"version"`
	DownloadURL    string         `json:"download_url"`
	ReleaseBase    string         `json:"release_base"`
	ClientConfig   string         `json:"client_config"`
	Commands       deployCommands `json:"commands"`
	Intune         deployIntune   `json:"intune"`
	Files          []string       `json:"files"`
	ConfigSHA256   string         `json:"config_sha256"`
	SelfSignedCert bool           `json:"self_signed"`
}

// deployClientConfig is the org's client configuration as the MSI
// would install it: the Windows writeback, temp folder and service
// match scripts/build-msi.ps1 so either installer can replace the other.
func deployClientConfig(org_config *config_proto.Config) (*config_proto.Config, error) {
	if org_config.Client == nil || len(org_config.Client.ServerUrls) == 0 {
		return nil, fmt.Errorf("this org has no client configuration (Client.server_urls is empty)")
	}
	client_config := config.StripClientConfig(org_config)
	client_config = proto.Clone(client_config).(*config_proto.Config)
	// The deployment certificate lets new agents through the agent
	// port's certificate check (services/agentmtls).
	client_config = agentmtls.WithDeploymentCert(org_config, client_config)

	c := client_config.Client
	c.WritebackWindows = deployWindowsBase + `\atlantiraptor.writeback.yaml`
	c.TempdirWindows = deployWindowsBase + `\Tools`
	c.WindowsInstaller = &config_proto.WindowsInstallerConfig{
		ServiceName:        "Atlantiraptor",
		InstallPath:        deployWindowsBase + `\Atlantiraptor.exe`,
		ServiceDescription: "Atlantiraptor endpoint agent by Atlant Security",
	}
	return client_config, nil
}

func deployReleaseBase() (string, string) {
	version := config.ReleaseVersion()
	if deployVersionRegex.MatchString(version) {
		return version, "https://github.com/" + selfupdate.Repository + "/releases/download/v" + version
	}
	// Development builds have no matching release; use the latest one.
	return "", "https://github.com/" + selfupdate.Repository + "/releases/latest/download"
}

// isLocalOnlyURL reports whether a server URL can only be reached from
// the server itself.
func isLocalOnlyURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// commentSafe makes a value safe to put in a script comment: one line,
// printable, and no PowerShell block comment terminator.
func commentSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.ReplaceAll(s, "#>", "# >")
}

type deployBundle struct {
	info   deployInfo
	config []byte
	render func(name string) ([]byte, error)
}

func newDeployBundle(org_config *config_proto.Config, now time.Time) (*deployBundle, error) {
	client_config, err := deployClientConfig(org_config)
	if err != nil {
		return nil, err
	}
	serialized, err := yaml.Marshal(client_config)
	if err != nil {
		return nil, err
	}

	version, release_base := deployReleaseBase()
	org_id, org_name := org_config.OrgId, org_config.OrgName
	if utils.IsRootOrg(org_id) {
		org_id, org_name = "root", "root"
	}

	local_only := true
	for _, u := range client_config.Client.ServerUrls {
		if !isLocalOnlyURL(u) {
			local_only = false
		}
	}

	data := map[string]string{
		"Generated":   now.UTC().Format("2006-01-02 15:04 UTC"),
		"OrgName":     commentSafe(org_name),
		"ServerURLs":  commentSafe(strings.Join(client_config.Client.ServerUrls, ", ")),
		"DownloadURL": release_base + "/" + deployWindowsAsset,
		"ReleaseBase": release_base,
		"ConfigB64":   base64.StdEncoding.EncodeToString(serialized),
	}

	render := func(name string) ([]byte, error) {
		switch name {
		case deployConfigFile:
			return serialized, nil
		case deployWindowsFile, deployDetectFile, deployLinuxFile, deployMacFile:
			raw, err := deployTemplates.ReadFile("deploy_templates/" + name)
			if err != nil {
				return nil, err
			}
			raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
			tmpl, err := template.New(name).Option("missingkey=error").Parse(string(raw))
			if err != nil {
				return nil, err
			}
			out := &bytes.Buffer{}
			if err := tmpl.Execute(out, data); err != nil {
				return nil, err
			}
			res := out.Bytes()
			if strings.HasSuffix(name, ".ps1") {
				// Windows line endings and a BOM, so Windows
				// PowerShell 5.1 reads the file as UTF-8.
				res = append([]byte("\xef\xbb\xbf"), bytes.ReplaceAll(res, []byte("\n"), []byte("\r\n"))...)
			}
			return res, nil
		}
		return nil, fmt.Errorf("unknown file %q", name)
	}

	windows, err := render(deployWindowsFile)
	if err != nil {
		return nil, err
	}
	linux, err := render(deployLinuxFile)
	if err != nil {
		return nil, err
	}
	macos, err := render(deployMacFile)
	if err != nil {
		return nil, err
	}

	b64 := base64.StdEncoding.EncodeToString
	// The PowerShell one-liner runs the same script as a script block,
	// so `return` ends it without closing the administrator's window.
	windows_script := bytes.TrimPrefix(windows, []byte("\xef\xbb\xbf"))

	self_signed := client_config.Client.UseSelfSignedSsl
	info := deployInfo{
		OrgId:          org_id,
		OrgName:        org_name,
		ServerURLs:     client_config.Client.ServerUrls,
		LocalOnly:      local_only,
		Version:        version,
		DownloadURL:    data["DownloadURL"],
		ReleaseBase:    release_base,
		ClientConfig:   string(serialized),
		ConfigSHA256:   fmt.Sprintf("%x", sha256.Sum256(serialized)),
		SelfSignedCert: self_signed,
		Commands: deployCommands{
			Windows: "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
				b64(windows_script) + "'))))",
			Linux: "echo '" + b64(linux) + "' | base64 -d | sudo sh",
			MacOS: "echo '" + b64(macos) + "' | base64 --decode | sudo sh",
		},
		Intune: deployIntune{
			SetupFile:        deployWindowsFile,
			InstallCommand:   "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\" + deployWindowsFile,
			UninstallCommand: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\" + deployWindowsFile + " -Uninstall",
		},
		Files: []string{deployConfigFile, deployWindowsFile, deployIntuneFile, deployDetectFile, deployLinuxFile, deployMacFile},
	}

	bundle := &deployBundle{info: info, config: serialized}
	bundle.render = func(name string) ([]byte, error) {
		if name == deployIntuneFile {
			return intunewin.Build([]intunewin.File{{Name: deployWindowsFile, Data: windows}},
				deployWindowsFile, now)
		}
		return render(name)
	}
	return bundle, nil
}

func deployHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET only"})
			return
		}
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}
		org_id := r.Header.Get("Grpc-Metadata-OrgId")
		if org_id == "" {
			org_id = r.URL.Query().Get("org_id")
		}
		org_manager, err := services.GetOrgManager()
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		org_config, err := org_manager.GetOrgConfig(org_id)
		if err != nil {
			groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown org."})
			return
		}
		if ok, err := services.CheckAccess(org_config, principal, acls.SERVER_ADMIN); err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{
				"message": "Only server administrators can see the client configuration and install commands."})
			return
		}

		bundle, err := newDeployBundle(org_config, time.Now())
		if err != nil {
			groupsJSON(w, http.StatusConflict, map[string]string{"message": err.Error()})
			return
		}

		name := r.URL.Query().Get("file")
		if !utils.InString(bundle.info.Files, name) && name != "" {
			groupsJSON(w, http.StatusNotFound, map[string]string{"message": "Unknown file."})
			return
		}

		operation := "client_deploy_view"
		if name != "" {
			operation = "client_deploy_download"
		}
		if err := services.LogAudit(r.Context(), org_config, principal, operation,
			ordereddict.NewDict().Set("file", name)); err != nil {
			logging.GetLogger(org_config, &logging.FrontendComponent).Error("%v %v", operation, principal)
		}

		w.Header().Set("Cache-Control", "no-store")
		if name == "" {
			groupsJSON(w, http.StatusOK, bundle.info)
			return
		}

		data, err := bundle.render(name)
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		content_type := "text/plain; charset=utf-8"
		if name == deployIntuneFile {
			content_type = "application/octet-stream"
		}
		w.Header().Set("Content-Type", content_type)
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}
