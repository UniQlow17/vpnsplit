//go:build windows

package config

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedInstaller is the service account that owns the files of Windows and
// of installed components.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// trustedOwner: the owner of the object is SYSTEM, Administrators or TrustedInstaller.
func trustedOwner(_ os.FileInfo, path string) bool {
	trusted, err := trustedSIDs()
	if err != nil {
		return false
	}
	if ti, err := windows.StringToSid(trustedInstaller); err == nil {
		trusted = append(trusted, ti)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	return err == nil && inSIDs(owner, trusted)
}

// Access rights that let somebody change a file or a directory (or what is in
// it) or its owner and access list.
const (
	rightWriteData   = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	rightAppendData  = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	rightDeleteChild = 0x00000040
	rightDelete      = 0x00010000
	rightWriteDAC    = 0x00040000
	rightWriteOwner  = 0x00080000
	rightGenericAll  = 0x10000000
	rightGenericWr   = 0x40000000
	writeRights      = rightWriteData | rightAppendData | rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWr

	aceInheritOnly = 0x08
)

// trustedWriters is who may hold write rights: SYSTEM, Administrators,
// TrustedInstaller, and CREATOR OWNER (the owner is checked to be one of the
// first three).
func trustedWriters() ([]*windows.SID, error) {
	trusted, err := trustedSIDs()
	if err != nil {
		return nil, err
	}
	for _, s := range []string{trustedInstaller, "S-1-3-0"} {
		if sid, err := windows.StringToSid(s); err == nil {
			trusted = append(trusted, sid)
		}
	}
	return trusted, nil
}

// strictSD reports whether the owner is SYSTEM, Administrators or
// TrustedInstaller and nobody else is granted a right to write, delete, or
// change the access list or the owner.
func strictSD(sd *windows.SECURITY_DESCRIPTOR) bool {
	trusted, err := trustedWriters()
	if err != nil || sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !inSIDs(owner, trusted[:len(trusted)-1]) { // not CREATOR OWNER as an owner
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false // no list at all means everybody may do everything
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
				continue // applies to what is created below, not to this object
			}
			if ace.Mask&writeRights != 0 && !inSIDs((*windows.SID)(unsafe.Pointer(&ace.SidStart)), trusted) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// machineFileOK judges the open file by its handle: owner and access list.
func machineFileOK(f *os.File, _ os.FileInfo) bool {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && strictSD(sd)
}

// strictDir: the access list of the directory lets nobody but the system write.
func strictDir(path string) bool {
	d, err := os.Open(path)
	if err != nil {
		return false
	}
	defer d.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(d.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && strictSD(sd)
}

// userOwned: the files of a profile are protected by the ACL of the profile,
// not checked file by file.
func userOwned(os.FileInfo) bool { return true }
