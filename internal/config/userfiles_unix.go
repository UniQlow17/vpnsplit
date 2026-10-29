//go:build unix

package config

import (
	"os"
	"syscall"
)

// trustedOwner: the object belongs to root, nobody but the owner can write it
// and (macOS) no extended access list gives anybody else a right to it.
func trustedOwner(fi os.FileInfo, path string) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0 && noExtendedACL(path)
}

// machineFileOK judges the open file by its descriptor: root's, and not
// writable by group or others.
func machineFileOK(f *os.File, fi os.FileInfo) bool { return trustedOwner(fi, f.Name()) }

// strictDir: on Unix trustedOwner already looks at the rights of the directory.
func strictDir(string) bool { return true }

// userOwned: the file belongs to the real user (the one behind sudo or
// pkexec, or the user of the process) or to root.
func userOwned(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := os.Getuid()
	if o := sudoOwner(); o != nil {
		uid = o.uid
	}
	return int(st.Uid) == uid || st.Uid == 0
}
