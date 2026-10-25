//go:build darwin

package netif

import (
	"os/exec"
	"strings"
)

// owners names the app behind utun adapters it can be sure about:
//
//  1. Network Extension VPNs (BlancVPN, WireGuard, Outline...) are listed by
//     the system configuration together with their interface.
//  2. Other clients open the utun themselves; lsof shows which process holds
//     it (for root-owned daemons such as Check Point or Happ only under sudo).
//
// It also returns the running processes for guessing the rest.
func owners([]Info) (map[string]string, []string) {
	res := map[string]string{}

	if out, err := exec.Command("scutil", "--nc", "list").Output(); err == nil {
		for _, s := range parseNCList(string(out)) {
			if !s.Connected {
				continue
			}
			ip, err := scutilShow("State:/Network/Service/" + s.ID + "/IPv4")
			if iface := parseSCValue(ip, "InterfaceName"); err == nil && iface != "" {
				name := s.Name
				if p, ok := findProvider(s.Name + " " + s.Bundle); ok {
					name = p.Name
				}
				res[iface] = name
			}
		}
	}

	procs := map[int]string{}
	if out, err := exec.Command("ps", "-axo", "pid=,comm=").Output(); err == nil {
		procs = parsePS(string(out))
	}
	if out, err := exec.Command("lsof", "-nP", "-w", "-F", "pn").Output(); err == nil || len(out) > 0 {
		for iface, pid := range parseLsofUtun(string(out)) {
			if _, done := res[iface]; !done {
				claim(res, iface, procs[pid])
			}
		}
	}

	var paths []string
	for _, p := range procs {
		paths = append(paths, p)
	}
	return res, paths
}

func scutilShow(key string) (string, error) {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("show " + key + "\n")
	out, err := cmd.Output()
	return string(out), err
}
