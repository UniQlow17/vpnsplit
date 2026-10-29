//go:build windows

package config

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// exeFileOK: the owner of the file is SYSTEM, Administrators or TrustedInstaller
// and nobody else may write it or change its access list (judged on the open handle).
func exeFileOK(f *os.File, fi os.FileInfo) bool { return machineFileOK(f, fi) }

// exeDirOK: the same for the directory the program is in, where a file put next
// to it (a DLL) would be loaded too.
func exeDirOK(dir string) bool { return machineDirOK(dir) }

// Rights that let somebody replace what is below a directory: delete or rename
// an entry of it, or change who may. Creating a new entry (FILE_ADD_FILE,
// FILE_ADD_SUBDIRECTORY) does not, and the root of a drive grants that to every
// user.
const replaceRights = rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWr

// ancestorDirOK: a directory above the program, up to the root of the drive,
// belongs to the system and nobody else may rename or delete what is in it or
// change its access list.
func ancestorDirOK(dir string) bool {
	d, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer d.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(d.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	return ancestorSD(sd)
}

func ancestorSD(sd *windows.SECURITY_DESCRIPTOR) bool {
	trusted, err := trustedWriters()
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !inSIDs(owner, trusted[:len(trusted)-1]) { // CREATOR OWNER does not own anything
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Header.AceFlags&aceInheritOnly != 0 {
				continue
			}
			if ace.Mask&replaceRights != 0 && !inSIDs((*windows.SID)(unsafe.Pointer(&ace.SidStart)), trusted) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
