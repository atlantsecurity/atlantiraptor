//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// relaunch starts the new binary hidden, in the background. It waits
// for this process to exit before it starts serving (see
// WaitForPreviousProcess). A Windows service is restarted through the
// service manager instead.
func relaunch(exe string, args []string, service_name string) error {
	is_service, _ := svc.IsWindowsService()
	if is_service {
		if service_name == "" {
			return fmt.Errorf("running as a service but the service name is unknown")
		}
		args = []string{"selfupdate", "restart-service", "--name", service_name}
	}

	start := func(flags uint32) error {
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), WaitPIDEnv+"="+strconv.Itoa(os.Getpid()))
		// Keep writing to the same log files if output was redirected.
		if os.Stdout != nil {
			cmd.Stdout = os.Stdout
		}
		if os.Stderr != nil {
			cmd.Stderr = os.Stderr
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: flags,
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}

	// Never a visible console window. Break away from a job object
	// (scheduled tasks, some launchers) so the new process survives
	// this one; not every job allows that.
	base := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP)
	err := start(base | windows.CREATE_BREAKAWAY_FROM_JOB)
	if err != nil {
		err = start(base)
	}
	return err
}

func waitForPID(pid int, timeout time.Duration) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// Already gone.
		return
	}
	defer windows.CloseHandle(h)
	_, _ = windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
}

// RestartService starts the named service once its old process has
// stopped. It runs in a short-lived helper process.
func RestartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()

	deadline := time.Now().Add(2 * time.Minute)
	for {
		status, err := s.Query()
		if err == nil {
			switch status.State {
			case svc.Running, svc.StartPending:
				return nil
			case svc.Stopped:
				err = s.Start()
				if err == nil {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("service %v did not stop", name)
			}
			return err
		}
		time.Sleep(time.Second)
	}
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}
