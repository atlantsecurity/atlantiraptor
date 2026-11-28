//go:build !windows

package selfupdate

import "errors"

// AgentUpgradeSupported reports whether this platform can upgrade an
// installed agent in place. Only Windows release binaries are
// published and signed so far.
const AgentUpgradeSupported = false

var errAgentUnsupported = errors.New("automatic agent upgrades are only supported on Windows")

func AgentUpgrade(version, service_name string) (string, error) {
	return "", errAgentUnsupported
}

func AgentApply(version, service_name string) error {
	return errAgentUnsupported
}
