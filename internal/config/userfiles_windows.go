//go:build windows

package config

import (
	"os"

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

// userOwned: the files of a profile are protected by the ACL of the profile,
// not checked file by file.
func userOwned(os.FileInfo) bool { return true }
