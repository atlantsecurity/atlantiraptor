package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestStripClientConfigGivesAgentServiceName(t *testing.T) {
	server := GetDefaultConfig()
	server.Client.WindowsInstaller = ServerWindowsInstaller()

	client := StripClientConfig(server)
	assert.Equal(t, AgentServiceName, client.Client.WindowsInstaller.ServiceName)
	assert.Equal(t, AgentInstallPath, client.Client.WindowsInstaller.InstallPath)

	// The server config itself is not changed.
	assert.Equal(t, ServerServiceName, server.Client.WindowsInstaller.ServiceName)
}

func TestStripClientConfigKeepsOtherServiceNames(t *testing.T) {
	// Older configs keep their names, so existing agents are not renamed.
	server := GetDefaultConfig()
	server.Client.WindowsInstaller = &config_proto.WindowsInstallerConfig{
		ServiceName: "Velociraptor",
		InstallPath: `$ProgramFiles\Velociraptor\Velociraptor.exe`,
	}
	client := StripClientConfig(server)
	assert.Equal(t, "Velociraptor", client.Client.WindowsInstaller.ServiceName)
}
