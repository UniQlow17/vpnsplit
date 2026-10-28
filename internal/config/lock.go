package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const lockFile = "vpnsplit.lock"

// ErrLocked means another running vpnsplit holds the lock of the journal.
var ErrLocked = errors.New("another vpnsplit is running and owns the routes")

// Lock is the exclusive lock of the journal directory. The OS drops it when
// the process dies, however it dies, so a held lock means a live owner.
type Lock struct{ f *os.File }

// LockState takes the lock of the protected journal directory (creating it:
// administrator rights are needed). It fails with ErrLocked at once if
// somebody else holds it.
func LockState() (*Lock, error) {
	dir, err := StateDir(true)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	return lockDir(dir)
}

func lockDir(dir string) (*Lock, error) {
	f, err := openLockFile(filepath.Join(dir, lockFile))
	if err != nil {
		return nil, err
	}
	if err := lockFileExclusive(f); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock; it is safe to call more than once.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	err := unlockFile(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
