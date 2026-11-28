//go:build !windows

package auditlog

import (
	"io"
	"os"
	"syscall"
)

type unixLock struct{ fd *os.File }

func (l *unixLock) Close() error {
	_ = syscall.Flock(int(l.fd.Fd()), syscall.LOCK_UN)
	return l.fd.Close()
}

// lockDir takes an exclusive lock on the directory's lock file.
func lockDir(path string) (io.Closer, error) {
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fd.Close()
		return nil, err
	}
	return &unixLock{fd: fd}, nil
}
