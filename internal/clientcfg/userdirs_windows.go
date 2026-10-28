//go:build windows

package clientcfg

import (
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

// userDirs returns the configuration directory (%AppData%) and the profile of
// the user at the screen. For a process that runs as another account (UAC with
// the credentials of an administrator) these are the directories of that user
// as the registry names them; when that cannot be told, those of the process.
func userDirs() (cfgDir, home string) {
	cfgDir, _ = config.RealUserConfigDir()
	home, _ = config.RealUserHome()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return cfgDir, home
	}
	sid, err := sessionUserSID()
	if err != nil || sid == nil || sid.Equals(tu.User.Sid) {
		return cfgDir, home
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList+sid.String(), registry.QUERY_VALUE)
	if err != nil {
		return "", "" // another account and its profile is unknown: its files are not guessed
	}
	defer k.Close()
	p, _, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", ""
	}
	if p, err = registry.ExpandString(p); err != nil || !filepath.IsAbs(p) {
		return "", ""
	}
	return filepath.Join(p, "AppData", "Roaming"), p
}
