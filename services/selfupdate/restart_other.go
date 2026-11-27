//go:build !windows

package selfupdate

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func relaunch(exe string, args []string, service_name string) error {
	return errUnsupported
}

func waitForPID(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p, err := os.FindProcess(pid)
		if err != nil || p.Signal(syscall.Signal(0)) != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func RestartService(name string) error {
	return errUnsupported
}

func hideWindow(cmd *exec.Cmd) {}
