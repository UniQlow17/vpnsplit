//go:build windows

package clientcfg

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	inetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	gpoNRPT      = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	wtsUserName   = 5 // WTS_INFO_CLASS
	wtsDomainName = 7
)

var (
	wtsapi     = windows.NewLazySystemDLL("wtsapi32.dll")
	pWTSQuery  = wtsapi.NewProc("WTSQuerySessionInformationW")
	pWTSFreeMe = wtsapi.NewProc("WTSFreeMemory")
)

// sessionUserSID is the SID of the user who owns the session of this process.
// An elevated process started through UAC by another administrator account
// has the profile of that account (HKCU), while the settings that matter are
// those of the person at the screen.
func sessionUserSID() (*windows.SID, error) {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return nil, err
	}
	query := func(class uintptr) (string, error) {
		var buf *uint16
		var n uint32
		r, _, err := pWTSQuery.Call(0, uintptr(session), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			return "", err
		}
		defer pWTSFreeMe.Call(uintptr(unsafe.Pointer(buf)))
		return windows.UTF16PtrToString(buf), nil
	}
	user, err := query(wtsUserName)
	if err != nil || user == "" {
		return nil, err
	}
	domain, _ := query(wtsDomainName)
	name := user
	if domain != "" {
		name = domain + `\` + user
	}
	sid, _, _, err := windows.LookupSID("", name)
	return sid, err
}

// userHive returns the registry key that holds the settings of the user at
// the screen (HKCU, or the hive of that user in HKEY_USERS when the process
// runs as another account). ok is false when that hive cannot be told.
func userHive() (root registry.Key, sub string, ok bool) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, "", false
	}
	sid, err := sessionUserSID()
	if err != nil || sid == nil || sid.Equals(tu.User.Sid) {
		return registry.CURRENT_USER, "", true // the same account (or the session user is not known: HKCU is the best that there is)
	}
	return registry.USERS, sid.String() + `\`, true
}

// readProxy reads WinINET: ProxyEnable, ProxyServer and AutoConfigURL, the
// settings that Windows, browsers and most clients' "system proxy" mode use.
func readProxy() Proxy {
	root, sub, ok := userHive()
	if !ok {
		return Proxy{}
	}
	k, err := registry.OpenKey(root, sub+inetSettings, registry.QUERY_VALUE)
	if err != nil {
		return Proxy{}
	}
	defer k.Close()
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	pac, _, _ := k.GetStringValue("AutoConfigURL")
	return WinINETProxy(enable, server, pac)
}

// readGPONRPT counts the NRPT rules that Group Policy sets. Their existence is
// enough to know that the local rules are not used.
func readGPONRPT() (known bool, rules int) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, gpoNRPT, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return true, 0
		}
		return false, 0
	}
	defer k.Close()
	st, err := k.Stat()
	if err != nil {
		return false, 0
	}
	return true, int(st.SubKeyCount)
}
