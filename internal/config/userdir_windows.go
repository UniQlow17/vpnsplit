//go:build windows

package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// sudoOwner: there is no sudo on Windows, files stay with the elevated user.
func sudoOwner() *owner { return nil }

func userDir() (string, *owner, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(d, "vpnsplit"), nil, nil
}

// legacyDirs lists where older versions kept the journal.
func legacyDirs() []string {
	if p, _, err := userDir(); err == nil {
		return []string{p}
	}
	return nil
}

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// cacheWritable: an elevated process does not write caches into the user's
// profile, a directory a non-elevated process of the same user can swap for
// a junction; Windows has no directory-relative rename to rule that out.
func cacheWritable() bool { return !isElevated() }
