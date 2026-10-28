//go:build windows

package config

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func lockFileExclusive(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
