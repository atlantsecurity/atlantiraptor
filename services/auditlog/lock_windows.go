//go:build windows

package auditlog

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

type winLock struct{ fd *os.File }

func (l *winLock) Close() error {
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(l.fd.Fd()), 0, 1, 0, ol)
	return l.fd.Close()
}

// lockDir takes an exclusive lock on the directory's lock file.
func lockDir(path string) (io.Closer, error) {
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(fd.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		fd.Close()
		return nil, err
	}
	return &winLock{fd: fd}, nil
}
