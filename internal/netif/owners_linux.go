//go:build linux

package netif

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// owners names the program behind tun adapters it can be sure about:
//
//  1. NetworkManager lists its VPN and WireGuard connections with their device.
//  2. A process holding /dev/net/tun shows the adapter in its fdinfo ("iff:");
//     for daemons of other users this needs root.
//
// It also returns the running processes for guessing the rest.
func owners(ifs []Info) (map[string]string, []string) {
	res := map[string]string{}
	if out, err := sysexec.Command("nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active").Output(); err == nil {
		for iface, name := range parseNMActive(string(out)) {
			if Classify(iface) != KindPhysical {
				if p, ok := findProvider(name); ok {
					name = p.Name
				}
				res[iface] = name
			}
		}
	}

	var procs []string
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		dir := filepath.Join("/proc", d.Name())
		path := procPath(dir)
		if path == "" {
			continue
		}
		procs = append(procs, path)
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, _ := os.Readlink(filepath.Join(dir, "fd", fd.Name())); l != "/dev/net/tun" {
				continue
			}
			info, _ := os.ReadFile(filepath.Join(dir, "fdinfo", fd.Name()))
			if iface := parseFdinfoIff(string(info)); iface != "" && res[iface] == "" {
				claim(res, iface, path)
			}
		}
	}
	return res, procs
}

// procPath is the executable of a process; the exe link is hidden for other
// users' processes, argv[0] is not.
func procPath(dir string) string {
	if p, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		return p
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	argv0, _, _ := strings.Cut(string(b), "\x00")
	return argv0
}
