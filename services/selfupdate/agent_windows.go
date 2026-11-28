//go:build windows

package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"www.velocidex.com/golang/velociraptor/config"
)

// AgentUpgradeSupported reports whether this platform can upgrade an
// installed agent in place.
const AgentUpgradeSupported = true

// How long the apply step waits before stopping the agent, so the
// agent can send the results of the collection that started it.
var agentApplyDelay = 15 * time.Second

// AgentUpgrade is the first step of an agent upgrade. It runs in the
// new binary, which the agent's upgrade artifact
// (Admin.Client.Upgrade.Atlantiraptor) has downloaded from the server,
// checked against the tool hash and the Atlant Security signature, and
// copied next to the installed agent. It checks everything again, then
// starts itself detached to do the swap (AgentApply) and returns, so
// the collection can finish before the agent is stopped.
func AgentUpgrade(version, service_name string) (string, error) {
	self, installed, err := agentPaths(version, service_name)
	if err != nil {
		return "", err
	}
	subject, err := VerifyBinary(self)
	if err != nil {
		return "", err
	}

	args := []string{"selfupdate", "agent-upgrade",
		"--version", version, "--service", service_name, "--apply"}
	start := func(flags uint32) error {
		cmd := exec.Command(self, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: flags,
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	// Detached from the agent: the agent is stopped during the swap.
	base := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP |
		windows.DETACHED_PROCESS)
	if err := start(base | windows.CREATE_BREAKAWAY_FROM_JOB); err != nil {
		if err := start(base); err != nil {
			return "", fmt.Errorf("starting the upgrade: %w", err)
		}
	}
	return fmt.Sprintf("Verified %v (signed by %v). Replacing %v and restarting service %v in %v.",
		version, subject, installed, service_name, agentApplyDelay), nil
}

// agentPaths returns this binary and the installed agent it replaces,
// after checking that this binary is the expected version and sits in
// the installed agent's folder (which only SYSTEM and Administrators
// can write to).
func agentPaths(version, service_name string) (self, installed string, err error) {
	if config.ReleaseVersion() == "" || config.ReleaseVersion() != version {
		return "", "", fmt.Errorf("this binary is version %q, not %v",
			config.ReleaseVersion(), version)
	}
	self, err = executablePath()
	if err != nil {
		return "", "", err
	}
	installed, err = serviceExecutable(service_name)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(filepath.Dir(self), filepath.Dir(installed)) {
		return "", "", fmt.Errorf("%v is not in the agent's folder %v",
			self, filepath.Dir(installed))
	}
	if strings.EqualFold(self, installed) {
		return "", "", errors.New("run the upgrade from a copy, not the installed agent")
	}
	return self, installed, nil
}

// serviceExecutable returns the program a service runs.
func serviceExecutable(name string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return "", fmt.Errorf("service %v: %w", name, err)
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", err
	}
	path := ServiceBinaryFromCommandLine(c.BinaryPathName)
	if path == "" {
		return "", fmt.Errorf("cannot read the program of service %v", name)
	}
	return filepath.Clean(path), nil
}

// AgentApply replaces the installed agent with this binary and
// restarts the service. If the new version does not stay running, the
// previous binary is put back. Progress goes to agent-upgrade.log in
// the agent's folder.
func AgentApply(version, service_name string) error {
	self, installed, err := agentPaths(version, service_name)
	if err != nil {
		return err
	}
	log_fd, _ := os.OpenFile(filepath.Join(filepath.Dir(installed), "agent-upgrade.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	logf := func(format string, args ...interface{}) {
		if log_fd != nil {
			fmt.Fprintf(log_fd, "%v %v\n", time.Now().UTC().Format(time.RFC3339),
				fmt.Sprintf(format, args...))
		}
	}
	defer func() {
		if log_fd != nil {
			log_fd.Close()
		}
	}()

	err = agentApply(self, installed, version, service_name, logf)
	if err != nil {
		logf("upgrade to %v failed: %v", version, err)
		return err
	}
	logf("upgraded to %v", version)
	return nil
}

func agentApply(self, installed, version, service_name string,
	logf func(string, ...interface{})) error {
	logf("upgrading %v to %v", installed, version)
	time.Sleep(agentApplyDelay)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(service_name)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := stopService(s, 2*time.Minute); err != nil {
		_ = s.Start()
		return fmt.Errorf("stopping the agent: %w", err)
	}

	old := installed + ".old"
	_ = os.Remove(old)
	// The stopped process can hold the file for a moment.
	err = retry(30*time.Second, func() error { return os.Rename(installed, old) })
	if err != nil {
		_ = s.Start()
		return fmt.Errorf("moving the old agent aside: %w", err)
	}
	if err := copyFile(self, installed); err != nil {
		_ = os.Remove(installed)
		_ = os.Rename(old, installed)
		_ = s.Start()
		return fmt.Errorf("putting the new agent in place: %w", err)
	}

	if err := startAndWatch(s, 2*time.Minute, 30*time.Second); err != nil {
		logf("the new agent did not stay running (%v); restoring the previous one", err)
		_ = stopService(s, time.Minute)
		_ = retry(30*time.Second, func() error {
			err := os.Remove(installed)
			if os.IsNotExist(err) {
				return nil
			}
			return err
		})
		if rerr := os.Rename(old, installed); rerr != nil {
			return fmt.Errorf("%v; restoring the previous agent also failed: %w", err, rerr)
		}
		_ = s.Start()
		return fmt.Errorf("the new agent did not stay running, the previous one was restored: %w", err)
	}

	_ = os.Remove(old)
	// This copy is still running; Windows removes it at the next restart
	// and the next upgrade overwrites it anyway.
	if p, err := windows.UTF16PtrFromString(self); err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	return nil
}

func stopService(s *mgr.Service, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err == nil && status.State == svc.Stopped {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("the service did not stop")
}

// startAndWatch starts the service and requires it to keep running
// for settle once it is up.
func startAndWatch(s *mgr.Service, timeout, settle time.Duration) error {
	if err := s.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	var running_since time.Time
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return err
		}
		switch status.State {
		case svc.Running:
			if running_since.IsZero() {
				running_since = time.Now()
			}
			if time.Since(running_since) >= settle {
				return nil
			}
		case svc.StartPending:
		default:
			return fmt.Errorf("the service is in state %v", status.State)
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("the service did not start in time")
}

func retry(timeout time.Duration, cb func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := cb()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Second)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
