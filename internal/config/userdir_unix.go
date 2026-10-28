//go:build unix

package config

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

// sudoOwner returns the user on whose behalf a root process runs (SUDO_USER
// or PKEXEC_UID), or nil when the process is not root, or is root itself.
// HOME is not trusted: under sudo it is often still /root.
func sudoOwner() *owner {
	if os.Geteuid() != 0 {
		return nil
	}
	var u *user.User
	var err error
	switch {
	case os.Getenv("SUDO_USER") != "":
		u, err = user.Lookup(os.Getenv("SUDO_USER"))
	case os.Getenv("PKEXEC_UID") != "":
		u, err = user.LookupId(os.Getenv("PKEXEC_UID"))
	default:
		return nil
	}
	if err != nil || u.Uid == "0" || !filepath.IsAbs(u.HomeDir) {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &owner{uid: uid, gid: gid, home: u.HomeDir}
}

// userConfigDir is the per-user configuration base of home on this OS.
func userConfigDir(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support")
	}
	return filepath.Join(home, ".config")
}

// userDir is the vpnsplit directory of the real user and, under sudo, its owner.
func userDir() (string, *owner, error) {
	if o := sudoOwner(); o != nil {
		return filepath.Join(userConfigDir(o.home), "vpnsplit"), o, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(d, "vpnsplit"), nil, nil
}

// legacyDirs lists where older versions kept the journal.
func legacyDirs() []string {
	var out []string
	if d, err := os.UserConfigDir(); err == nil {
		out = append(out, filepath.Join(d, "vpnsplit"))
	}
	if p, _, err := userDir(); err == nil && (len(out) == 0 || out[0] != p) {
		out = append(out, p)
	}
	return out
}

func isElevated() bool { return os.Geteuid() == 0 }

// cacheWritable: under sudo the write goes through os.Root inside the home
// of the real user (see writeFileAtomic), so links cannot redirect it.
func cacheWritable() bool { return true }
