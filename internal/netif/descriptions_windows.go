//go:build windows

package netif

import (
	"encoding/json"

	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// descriptions maps adapter name to its driver description (Get-NetAdapter),
// which is where names like "Check Point Virtual Network Adapter" live.
func descriptions() map[string]string {
	m := map[string]string{}
	out, err := sysexec.PowerShell(
		"Get-NetAdapter | Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress", nil).Output()
	if err != nil {
		return m
	}
	var arr []struct{ Name, InterfaceDescription string }
	if json.Unmarshal(out, &arr) != nil {
		var one struct{ Name, InterfaceDescription string }
		if json.Unmarshal(out, &one) == nil {
			arr = append(arr, one)
		}
	}
	for _, a := range arr {
		m[a.Name] = a.InterfaceDescription
	}
	return m
}
