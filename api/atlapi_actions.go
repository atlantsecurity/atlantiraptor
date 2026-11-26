package api

// The catalogue of response actions and quick-triage collections the API
// exposes, so a SIEM/SOAR can list them, show them as choices, and run
// one. It mirrors the console's Response page and quick triage tiles.

type APIActionField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
}

type APIAction struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"` // "response" or "triage"
	Group       string            `json:"group"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Platforms   string            `json:"platforms"`
	Artifacts   []string          `json:"artifacts"`
	Fixed       map[string]string `json:"fixed_parameters,omitempty"`
	Fields      []APIActionField  `json:"parameters"`
	ArmParam    string            `json:"dry_run_parameter,omitempty"`
	Live        bool              `json:"changes_endpoints"`
}

var quarantineArtifacts = []string{"Windows.Remediation.Quarantine", "Linux.Remediation.Quarantine", "MacOS.Remediation.Quarantine"}

var apiActions = []APIAction{
	// Response actions.
	{ID: "quarantine", Kind: "response", Group: "Containment", Title: "Network quarantine", Live: true,
		Description: "Cut hosts off from the network except for this server.", Platforms: "Windows, Linux, macOS",
		Artifacts: quarantineArtifacts,
		Fields:    []APIActionField{{Key: "MessageBox", Label: "Message shown to the user"}}},
	{ID: "unquarantine", Kind: "response", Group: "Containment", Title: "Lift quarantine", Live: true,
		Description: "Remove the quarantine policy.", Platforms: "Windows, Linux, macOS",
		Artifacts: quarantineArtifacts, Fixed: map[string]string{"RemovePolicy": "Y"}},
	{ID: "sinkhole", Kind: "response", Group: "Containment", Title: "DNS sinkhole", Live: true,
		Description: "Point domains at a sinkhole address via the hosts file.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.Sinkhole"},
		Fields: []APIActionField{{Key: "SinkholeTable", Label: "CSV: Domain,Sinkhole,Description", Required: true,
			Default: "Domain,Sinkhole,Description\nevil.example,127.0.0.1,C2 domain\n"}}},
	{ID: "unsinkhole", Kind: "response", Group: "Containment", Title: "Restore hosts file", Live: true,
		Description: "Undo a DNS sinkhole from the backup.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.Sinkhole"}, Fixed: map[string]string{"RestoreBackup": "Y"}},
	{ID: "kill", Kind: "response", Group: "Process", Title: "Kill process", Live: true, ArmParam: "ReallyDoIt",
		Description: "Terminate processes whose name or path matches a regex.", Platforms: "Windows, Linux, macOS",
		Artifacts: []string{"Generic.Remediation.KillProcess"},
		Fields: []APIActionField{
			{Key: "ProcessRegex", Label: "Process name or path (regex)", Required: true},
			{Key: "CommandLineRegex", Label: "Command line (regex)", Default: "."}}},
	{ID: "delete", Kind: "response", Group: "File", Title: "Delete file", Live: true, ArmParam: "ReallyDoIt",
		Description: "Delete files matching a glob, optionally only with a given SHA256.", Platforms: "Windows, Linux, macOS",
		Artifacts: []string{"Generic.Remediation.DeleteFile"},
		Fields: []APIActionField{
			{Key: "Glob", Label: "File glob", Required: true},
			{Key: "HashFilter", Label: "SHA256 (optional)"},
			{Key: "MaxFiles", Label: "Skip a host with more matches than", Default: "50"}}},
	{ID: "tasks", Kind: "response", Group: "Persistence", Title: "Remove scheduled tasks", Live: true, ArmParam: "ReallyDoIt",
		Description: "Delete scheduled tasks whose command and arguments match.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.ScheduledTasks"},
		Fields: []APIActionField{
			{Key: "CommandRegEx", Label: "Command (regex)", Required: true},
			{Key: "ArgumentRegex", Label: "Arguments (regex)", Default: "."}}},
	{ID: "service", Kind: "response", Group: "Persistence", Title: "Remove service", Live: true, ArmParam: "ReallyDoIt",
		Description: "Stop and delete services whose name or binary path matches.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.RemoveService"},
		Fields:    []APIActionField{{Key: "ServiceRegex", Label: "Service name or path (regex)", Required: true}}},
	{ID: "disable-user", Kind: "response", Group: "Accounts", Title: "Disable local user", Live: true, ArmParam: "ReallyDoIt",
		Description: "Disable local accounts whose name matches.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.DisableLocalUser"},
		Fields:    []APIActionField{{Key: "UserRegex", Label: "Account name (regex)", Required: true}}},
	{ID: "enable-user", Kind: "response", Group: "Accounts", Title: "Re-enable local user", Live: true, ArmParam: "ReallyDoIt",
		Description: "Re-enable local accounts that were disabled.", Platforms: "Windows",
		Artifacts: []string{"Windows.Remediation.DisableLocalUser"}, Fixed: map[string]string{"Enable": "Y"},
		Fields: []APIActionField{{Key: "UserRegex", Label: "Account name (regex)", Required: true}}},

	// Quick triage collections (read-only).
	{ID: "triage-processes", Kind: "triage", Group: "Triage", Title: "Processes", Platforms: "Windows",
		Description: "Running processes with hashes and signers.", Artifacts: []string{"Windows.System.Pslist"}},
	{ID: "triage-network", Kind: "triage", Group: "Triage", Title: "Network connections", Platforms: "Windows",
		Description: "Open sockets and owning processes.", Artifacts: []string{"Windows.Network.Netstat"}},
	{ID: "triage-autoruns", Kind: "triage", Group: "Triage", Title: "Autoruns", Platforms: "Windows",
		Description: "Programs that start automatically.", Artifacts: []string{"Windows.Sys.StartupItems"}},
	{ID: "triage-services", Kind: "triage", Group: "Triage", Title: "Services", Platforms: "Windows",
		Description: "Installed services and binaries.", Artifacts: []string{"Windows.System.Services"}},
	{ID: "triage-tasks", Kind: "triage", Group: "Triage", Title: "Scheduled tasks", Platforms: "Windows",
		Description: "Task Scheduler entries.", Artifacts: []string{"Windows.System.TaskScheduler"}},
	{ID: "triage-browser", Kind: "triage", Group: "Triage", Title: "Browser history", Platforms: "Windows",
		Description: "Chrome, Edge, Brave and Firefox history.",
		Artifacts:   []string{"Windows.Applications.Chrome.History", "Windows.Applications.Firefox.History"}},
	{ID: "triage-downloads", Kind: "triage", Group: "Triage", Title: "Downloads history", Platforms: "Windows",
		Description: "Browser downloads and Zone.Identifier evidence.",
		Artifacts:   []string{"Windows.Applications.Chrome.Downloads", "Windows.Applications.Firefox.Downloads", "Windows.Analysis.EvidenceOfDownload"}},
	{ID: "triage-execution", Kind: "triage", Group: "Triage", Title: "Recently run programs", Platforms: "Windows",
		Description: "Prefetch, Amcache, ShimCache, BAM, UserAssist.",
		Artifacts:   []string{"Windows.Forensics.Prefetch", "Windows.Forensics.Amcache", "Windows.Registry.AppCompatCache", "Windows.Forensics.Bam", "Windows.Registry.UserAssist"}},
	{ID: "triage-mft", Kind: "triage", Group: "Triage", Title: "MFT (time window)", Platforms: "Windows",
		Description: "File system entries changed inside a time window.", Artifacts: []string{"Windows.NTFS.MFT"},
		Fields: []APIActionField{
			{Key: "DateAfter", Label: "From (RFC 3339)", Required: true},
			{Key: "DateBefore", Label: "To (RFC 3339)", Required: true},
			{Key: "MFTDrive", Label: "Drive", Default: "C:"}}},
}

func findAPIAction(id string) *APIAction {
	for i := range apiActions {
		if apiActions[i].ID == id {
			return &apiActions[i]
		}
	}
	return nil
}
