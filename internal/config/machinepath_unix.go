//go:build unix

package config

import "os"

// exeFileOK: root's file that nobody but the owner can write.
func exeFileOK(f *os.File, fi os.FileInfo) bool { return trustedOwner(fi, f.Name()) }

// exeDirOK: the directory of the program is root's and not writable by group or others.
func exeDirOK(dir string) bool { return machineDirOK(dir) }

// ancestorDirOK: a directory above is root's and not writable by group or others
// (else a user could rename the one below it and put another in its place).
func ancestorDirOK(dir string) bool { return machineDirOK(dir) }
