//go:build windows

package netif

import (
	"encoding/json"
	"os/exec"
)

// descriptions maps adapter name to its driver description (Get-NetAdapter),
// which is where names like "Check Point Virtual Network Adapter" live.
func descriptions() map[string]string {
	m := map[string]string{}
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "+
			"Get-NetAdapter | Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress").Output()
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
