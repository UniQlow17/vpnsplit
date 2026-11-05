package clientcfg

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

const (
	// limits on what is read: files per pattern, and size of a file by kind
	maxGlobFiles = 40
	maxOvpnSize  = 256 << 10
	maxLogSize   = 2 << 20
	maxXMLSize   = 512 << 10

	maxDirEntries  = 256 // entries read of one directory
	maxOvpnSubdirs = 32  // profile folders of OpenVPN looked into
)

type fileSpec struct {
	client  string
	path    string
	machine bool // a place of the machine (read only if the system owns it), not of the user
}

// tunFiles lists where the configs of the clients live. cfgDir is the
// per-user configuration directory, home the profile; progData the machine-wide
// data directory of Windows.
func tunFiles(goos, cfgDir, home, progData string) []fileSpec {
	var out []fileSpec
	add := func(client string, parts ...string) {
		out = append(out, fileSpec{client: client, path: filepath.Join(parts...)})
	}
	sys := func(client string, parts ...string) {
		out = append(out, fileSpec{client: client, path: filepath.Join(parts...), machine: true})
	}
	if cfgDir != "" {
		add("sing-box", cfgDir, "sing-box", "config.json")
		add("Mihomo", cfgDir, "mihomo", "config.yaml")
		add("Mihomo", cfgDir, "clash", "config.yaml")
		for _, d := range []string{"io.github.clash-verge-rev.clash-verge-rev", "clash-verge"} {
			add("Mihomo", cfgDir, d, "clash-verge.yaml")
			add("Mihomo", cfgDir, d, "config.yaml")
		}
	}
	if home != "" {
		add("Mihomo", home, ".config", "mihomo", "config.yaml")
		add("Mihomo", home, ".config", "clash", "config.yaml")
	}
	switch goos {
	case "windows":
		if progData != "" {
			sys("sing-box", progData, "sing-box", "config.json")
		}
	case "darwin":
		sys("sing-box", "/usr/local/etc/sing-box/config.json")
		sys("sing-box", "/opt/homebrew/etc/sing-box/config.json")
		sys("Mihomo", "/usr/local/etc/mihomo/config.yaml")
		sys("Mihomo", "/opt/homebrew/etc/mihomo/config.yaml")
	default:
		sys("sing-box", "/etc/sing-box/config.json")
		sys("sing-box", "/usr/local/etc/sing-box/config.json")
		sys("Mihomo", "/etc/mihomo/config.yaml")
	}
	return out
}

// hiddifyDirs are the places Hiddify keeps the sing-box configuration it
// generates (the working directory of its core).
func hiddifyDirs(goos, cfgDir, home string) []string {
	var out []string
	if cfgDir != "" {
		out = append(out, filepath.Join(cfgDir, "app.hiddify.com"), filepath.Join(cfgDir, "Hiddify"))
	}
	if home != "" && goos == "linux" {
		out = append(out, filepath.Join(home, ".local", "share", "app.hiddify.com"))
	}
	if home != "" && goos == "darwin" {
		out = append(out, filepath.Join(home, "Library", "Containers", "app.hiddify.com", "Data", "Library", "Application Support", "app.hiddify.com"))
	}
	return out
}

// fsReader reads the files of the scan. The files of the user are opened
// through the profile as a root, with no link on the way and (on Unix) an owner
// that is the user or root; the files of the machine only when the system owns
// them and their directory.
type fsReader struct {
	bases []string // the profile and the config directory of the user
}

func newFSReader() fsReader {
	cfgDir, home := userDirs()
	return fsReader{bases: []string{home, cfgDir}}
}

// base is the first root the path lies in ("" if none).
func (r fsReader) base(path string) string {
	for _, b := range r.bases {
		if b == "" {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(b), filepath.Clean(path))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return b
		}
	}
	return ""
}

var errOutsideProfile = errors.New("outside the profile of the user")

func (r fsReader) read(path string, machine bool, max int64) ([]byte, error) {
	if machine {
		return config.ReadMachineFile(path, max)
	}
	b := r.base(path)
	if b == "" {
		return nil, errOutsideProfile
	}
	return config.ReadUserFile(b, path, max)
}

func (r fsReader) list(dir string, machine bool) ([]config.UserEntry, error) {
	if machine {
		return config.ListMachineDir(dir, maxDirEntries)
	}
	b := r.base(dir)
	if b == "" {
		return nil, errOutsideProfile
	}
	return config.ListUserDir(b, dir, maxDirEntries)
}

// glob lists the regular files of dir that match pattern (sorted; links,
// directories and the like are left out; at most maxGlobFiles).
func (r fsReader) glob(dir string, machine bool, pattern string) []string {
	ents, err := r.list(dir, machine)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.Regular {
			continue
		}
		if ok, _ := filepath.Match(pattern, e.Name); ok {
			out = append(out, filepath.Join(dir, e.Name))
		}
	}
	if len(out) > maxGlobFiles {
		out = out[:maxGlobFiles]
	}
	return out
}

func (r *Result) scanTun() {
	fs := newFSReader()
	cfgDir, home := userDirs()
	progData := ""
	if runtime.GOOS == "windows" {
		if progData = os.Getenv("ProgramData"); progData == "" {
			progData = `C:\ProgramData`
		}
	}
	files := tunFiles(runtime.GOOS, cfgDir, home, progData)
	for _, d := range hiddifyDirs(runtime.GOOS, cfgDir, home) {
		files = append(files, fileSpec{client: "Hiddify", path: filepath.Join(d, "current-config.json")},
			fileSpec{client: "Hiddify", path: filepath.Join(d, "data", "current-config.json")})
		for _, p := range fs.glob(filepath.Join(d, "data", "configs"), false, "*.json") {
			files = append(files, fileSpec{client: "Hiddify", path: p})
		}
	}
	seen := map[netip.Prefix]bool{}
	for _, f := range files {
		data, err := fs.read(f.path, f.machine, MaxConfigSize)
		if err != nil {
			continue
		}
		var c TunCfg
		if strings.HasSuffix(f.path, ".json") {
			c, err = ParseSingBox(data)
		} else {
			c, err = ParseMihomo(data)
		}
		if err != nil {
			continue
		}
		c.Client, c.Path = f.client, f.path
		r.Tun = append(r.Tun, c)
		for _, p := range c.FakeRanges {
			if !seen[p] && len(r.FakeRanges) < MaxFakeRanges {
				seen[p] = true
				r.FakeRanges = append(r.FakeRanges, p)
			}
		}
	}
}

func (r *Result) scanOvpn() {
	fs := newFSReader()
	_, home := userDirs()
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	type place struct {
		path    string
		machine bool
	}
	var cfgDirs, logDirs []place
	if home != "" {
		cfgDirs = append(cfgDirs, place{filepath.Join(home, "OpenVPN", "config"), false})
		logDirs = append(logDirs, place{filepath.Join(home, "OpenVPN", "log"), false})
	}
	cfgDirs = append(cfgDirs, place{filepath.Join(pf, "OpenVPN", "config"), true})
	logDirs = append(logDirs, place{filepath.Join(pf, "OpenVPN", "log"), true})
	var files []place
	for _, d := range cfgDirs {
		for _, f := range fs.glob(d.path, d.machine, "*.ovpn") {
			files = append(files, place{f, d.machine})
		}
		ents, err := fs.list(d.path, d.machine)
		if err != nil {
			continue
		}
		subs := 0
		for _, e := range ents {
			if e.Dir && subs < maxOvpnSubdirs { // a profile folder (the GUI keeps profile\profile.ovpn)
				subs++
				for _, f := range fs.glob(filepath.Join(d.path, e.Name), d.machine, "*.ovpn") {
					files = append(files, place{f, d.machine})
				}
			}
		}
	}
	for _, f := range files {
		if data, err := fs.read(f.path, f.machine, maxOvpnSize); err == nil && OvpnBlocksOutsideDNS(data) {
			r.OvpnBlockDNS = filepath.Base(f.path)
			return
		}
	}
	for _, d := range logDirs {
		for _, f := range fs.glob(d.path, d.machine, "*.log") {
			if data, err := fs.read(f, d.machine, maxLogSize); err == nil && OvpnLogPushedBlockOutsideDNS(data) {
				r.OvpnBlockDNS = filepath.Base(f)
				return
			}
		}
	}
}

// scanCisco reads the profiles of Cisco AnyConnect / Secure Client: a place of
// the machine, read only when the system owns the files.
func (r *Result) scanCisco() {
	fs := newFSReader()
	var dirs []string
	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		dirs = []string{
			filepath.Join(pd, "Cisco", "Cisco Secure Client", "VPN", "Profile"),
			filepath.Join(pd, "Cisco", "Cisco AnyConnect Secure Mobility Client", "Profile"),
		}
	default:
		dirs = []string{"/opt/cisco/secureclient/vpn/profile", "/opt/cisco/anyconnect/profile"}
	}
	for _, d := range dirs {
		for _, f := range fs.glob(d, true, "*.xml") {
			data, err := fs.read(f, true, maxXMLSize)
			if err != nil {
				continue
			}
			p, _ := ParseCiscoProfile(data) // what was found before an error counts
			r.CiscoFailClosed = r.CiscoFailClosed || p.FailClosed
			r.CiscoAlwaysOn = r.CiscoAlwaysOn || p.AlwaysOn
		}
	}
}
