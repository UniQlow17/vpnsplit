//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectedSDDL: protected DACL (no inheritance from ProgramData), full
// control for SYSTEM and Administrators only, inherited by files inside.
const protectedSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func secureStateDir(create bool) (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("find ProgramData: %w", err)
	}
	path := filepath.Join(pd, "vpnsplit")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if !create {
			return "", err
		}
		// ALREADY_EXISTS (someone created it meanwhile) is fine: the check below decides
		if err := createProtectedDir(path); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return "", fmt.Errorf("create %s: %w", path, err)
		}
	} else if err != nil {
		return "", err
	}
	if err := checkProtectedDir(path); err != nil {
		return "", err
	}
	return path, nil
}

// createProtectedDir creates the directory with the protected DACL already in
// place, so there is no window in which it is open. Administrators are made
// the owner when the token allows it.
func createProtectedDir(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var last error
	for _, sddl := range []string{"O:BA" + protectedSDDL, protectedSDDL} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		if last = windows.CreateDirectory(p, &sa); last == nil || errors.Is(last, windows.ERROR_ALREADY_EXISTS) {
			return last
		}
	}
	return last
}

func trustedSIDs() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, nil
}

func inSIDs(sid *windows.SID, list []*windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, t := range list {
		if windows.EqualSid(sid, t) {
			return true
		}
	}
	return false
}

// checkProtectedDir refuses a directory that is not a plain directory, is
// owned by anybody except SYSTEM or Administrators, or lets anybody else in.
func checkProtectedDir(path string) error {
	if err := checkDir(path); err != nil {
		return err
	}
	trusted, err := trustedSIDs()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read permissions of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !inSIDs(owner, trusted) {
		who := "unknown"
		if owner != nil {
			who = owner.String()
		}
		return fmt.Errorf("%s is owned by %s, not by SYSTEM or Administrators: refusing to use it (delete it as Administrator if it is yours)", path, who)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no restrictive access list, refusing to use it", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !inSIDs((*windows.SID)(unsafe.Pointer(&ace.SidStart)), trusted) {
				return fmt.Errorf("%s grants access to someone besides SYSTEM and Administrators, refusing to use it", path)
			}
		default:
			return fmt.Errorf("%s has an unexpected access entry type %d, refusing to use it", path, ace.Header.AceType)
		}
	}
	return nil
}
