package config

import (
	"google.golang.org/protobuf/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

// The client config is a reduced version of the server config with
// sensitive values removed.
func GetClientConfig(config_obj *config_proto.Config) *config_proto.Config {
	// Copy only settings relevant to the client from the main config.
	client_config := &config_proto.Config{
		Version:  config_obj.Version,
		Client:   config_obj.Client,
		Autoexec: config_obj.Autoexec,

		// The below are added at runtime..
		Remappings: config_obj.Remappings, // --remap flag.
		Verbose:    config_obj.Verbose,    // -v flag
		DebugMode:  config_obj.DebugMode,  // --debug flag

		// Logging is populated from the client specific section.
		Logging: config_obj.Client.Logging,
	}

	return client_config
}

// Produce a minima configuration for the client. This function is
// used to prepare a client config from the server config file
// (e.g. for packaging).
func StripClientConfig(config_obj *config_proto.Config) *config_proto.Config {
	// Copy only settings relevant to the client from the main config.
	client_config := &config_proto.Config{
		Version:  config_obj.Version,
		Client:   config_obj.Client,
		Autoexec: config_obj.Autoexec,
	}

	// The server's Windows service name lives in the same
	// Client.windows_installer section. Agents must never install
	// themselves under the server's service, so a client config made
	// from a server config gets the agent's own service instead.
	if config_obj.Client != nil && config_obj.Client.WindowsInstaller != nil &&
		config_obj.Client.WindowsInstaller.ServiceName == ServerServiceName {
		client := proto.Clone(config_obj.Client).(*config_proto.ClientConfig)
		client.WindowsInstaller = AgentWindowsInstaller()
		client_config.Client = client
	}

	return client_config
}

const (
	// The Windows service the server installs itself as
	// (server_service install), and where.
	ServerServiceName        = "AtlantiraptorServer"
	ServerInstallPath        = `$ProgramFiles\Atlantiraptor Server\AtlantiraptorServer.exe`
	ServerServiceDescription = "Atlantiraptor server by Atlant Security"

	// The endpoint agent's Windows service, as the MSI and the
	// console's Deploy a client installer set it up.
	AgentServiceName        = "Atlantiraptor"
	AgentInstallPath        = `$ProgramFiles\Atlant Security\Atlantiraptor\Atlantiraptor.exe`
	AgentServiceDescription = "Atlantiraptor endpoint agent by Atlant Security"
)

// ServerWindowsInstaller is the windows_installer section new server
// configurations get. Existing configurations keep whatever they have,
// so installed services are never renamed.
func ServerWindowsInstaller() *config_proto.WindowsInstallerConfig {
	return &config_proto.WindowsInstallerConfig{
		ServiceName:        ServerServiceName,
		InstallPath:        ServerInstallPath,
		ServiceDescription: ServerServiceDescription,
	}
}

// AgentWindowsInstaller is the windows_installer section of an agent.
func AgentWindowsInstaller() *config_proto.WindowsInstallerConfig {
	return &config_proto.WindowsInstallerConfig{
		ServiceName:        AgentServiceName,
		InstallPath:        AgentInstallPath,
		ServiceDescription: AgentServiceDescription,
	}
}

// Determine if the binary is running as a frontend. At a minimum we
// need a valid Frontend and Datastore sections.
func IsFrontend(config_obj *config_proto.Config) bool {
	return config_obj.Datastore != nil &&
		config_obj.Frontend != nil
}

// Determine if the binary is running as a client. At a minimum we
// need a valid Client section.
func IsClient(config_obj *config_proto.Config) bool {
	return config_obj.Client != nil
}
