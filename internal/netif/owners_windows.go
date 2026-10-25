//go:build windows

package netif

import (
	"os/exec"
	"strings"
)

// owners: wintun/TAP adapters do not tell which process created them, and the
// adapter description already names most clients ("Check Point Virtual
// Network Adapter"), so only the running processes are returned for guessing.
// Elevated processes hide their path from a normal user; their name is used then.
func owners([]Info) (map[string]string, []string) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-Process | ForEach-Object { if ($_.Path) { $_.Path } else { $_.ProcessName } }").Output()
	if err != nil {
		return nil, nil
	}
	var procs []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			procs = append(procs, l)
		}
	}
	return nil, procs
}
