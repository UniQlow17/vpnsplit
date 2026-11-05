package clientcfg

import (
	"strconv"
	"strings"
	"unicode"
)

// Proxy is the system-wide proxy setting of the user.
type Proxy struct {
	Known   bool   // the setting could be read
	Enabled bool   // a manual proxy is on
	Server  string // host:port (or a list) of the manual proxy, cleaned
	PAC     string // the address of an automatic configuration script, cleaned
	Source  string // where it was read: "WinINET", "scutil", "gsettings"
}

// On reports whether some proxy applies to the user's applications.
func (p Proxy) On() bool { return p.Known && (p.Enabled || p.PAC != "") }

// clean makes text taken from outside safe to show: printable characters
// only, at most max runes.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if !unicode.IsPrint(r) {
			r = ' '
		}
		if n >= max {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// ParseScutilProxy reads the output of `scutil --proxy` (macOS).
func ParseScutilProxy(out string) Proxy {
	vals := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && !strings.Contains(k, " ") {
			if _, dup := vals[k]; !dup {
				vals[k] = strings.TrimSpace(v)
			}
		}
	}
	p := Proxy{Known: len(vals) > 0, Source: "scutil"}
	var servers []string
	for _, kind := range []string{"HTTP", "HTTPS", "SOCKS", "FTP"} {
		if vals[kind+"Enable"] != "1" || vals[kind+"Proxy"] == "" {
			continue
		}
		s := clean(vals[kind+"Proxy"], 80)
		if port := vals[kind+"Port"]; port != "" {
			if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
				s += ":" + port
			}
		}
		servers = append(servers, s)
	}
	if len(servers) > 0 {
		p.Enabled, p.Server = true, strings.Join(servers, ", ")
	}
	if vals["ProxyAutoConfigEnable"] == "1" {
		p.PAC = clean(vals["ProxyAutoConfigURLString"], 120)
		if p.PAC == "" {
			p.PAC = "(on)"
		}
	}
	return p
}

// ParseGsettingsProxy reads `gsettings list-recursively org.gnome.system.proxy`.
func ParseGsettingsProxy(out string) Proxy {
	vals := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimSpace(l), " ", 3)
		if len(f) == 3 && strings.HasPrefix(f[0], "org.gnome.system.proxy") {
			vals[f[0]+" "+f[1]] = strings.Trim(strings.TrimSpace(f[2]), "'")
		}
	}
	p := Proxy{Known: len(vals) > 0, Source: "gsettings"}
	switch vals["org.gnome.system.proxy mode"] {
	case "manual":
		var servers []string
		for _, kind := range []string{"http", "https", "socks", "ftp"} {
			host := vals["org.gnome.system.proxy."+kind+" host"]
			if host == "" {
				continue
			}
			s := clean(host, 80)
			if port := vals["org.gnome.system.proxy."+kind+" port"]; port != "" && port != "0" {
				if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
					s += ":" + port
				}
			}
			servers = append(servers, s)
		}
		if len(servers) > 0 {
			p.Enabled, p.Server = true, strings.Join(servers, ", ")
		}
	case "auto":
		p.PAC = clean(vals["org.gnome.system.proxy autoconfig-url"], 120)
		if p.PAC == "" {
			p.PAC = "(on)"
		}
	}
	return p
}

// WinINETProxy builds the setting from the values of Internet Settings in the
// registry (ProxyEnable, ProxyServer, AutoConfigURL).
func WinINETProxy(enable uint64, server, pac string) Proxy {
	p := Proxy{Known: true, Source: "WinINET"}
	if enable != 0 && strings.TrimSpace(server) != "" {
		p.Enabled, p.Server = true, clean(server, 120)
	}
	p.PAC = clean(pac, 120)
	return p
}
