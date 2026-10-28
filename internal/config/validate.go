package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Everything that reaches a shell, a route command or a file name must pass
// through these validators first. They are deliberately strict white lists:
// anything outside the list is rejected, not escaped.

const maxDomainLen = 253

var (
	// optional wildcard, dot-separated labels of ASCII letters, digits,
	// hyphens and underscores (service names such as _dmarc.example.com;
	// the underscore is harmless: DNS data reaches commands as arguments or
	// environment values, never as script text)
	domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}$`)
	asRe     = regexp.MustCompile(`^AS[0-9]{1,10}$`)
)

// ValidDomain reports whether s is a lower-case ASCII domain name, optionally
// with a leading "*.". Internationalized names must be given as punycode.
func ValidDomain(s string) bool {
	return len(s) <= maxDomainLen && domainRe.MatchString(s)
}

// ValidZone reports whether s is a DNS zone that may be put into the OS DNS
// configuration: a domain without wildcard and without a leading dot.
func ValidZone(s string) bool {
	return ValidDomain(s) && !strings.HasPrefix(s, "*")
}

// ValidAS reports whether s is an autonomous system in canonical form: "AS" and
// digits without leading zeros ("AS49675").
func ValidAS(s string) bool { return asRe.MatchString(s) && !strings.HasPrefix(s, "AS0") }

// ParseIPv4 parses a plain dotted IPv4 address and returns its canonical form.
// IPv6, IPv4-in-IPv6, zones and anything with spaces are rejected.
func ParseIPv4(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return "", fmt.Errorf("%q is not an IPv4 address", clip(s))
	}
	return a.String(), nil
}

// ParseCIDR4 parses an IPv4 network and returns it in canonical form
// (host bits cleared).
func ParseCIDR4(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return "", fmt.Errorf("%q is not an IPv4 CIDR", clip(s))
	}
	return p.Masked().String(), nil
}

// ValidIface reports whether s can be used as an adapter selector or name.
// Real adapter names may contain Unicode and spaces (Windows), so only what
// could confuse a command line or a journal is rejected: control characters,
// a leading "-" and absurd length. Names are never put into script text.
func ValidIface(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || r == '�' {
			return false
		}
	}
	return true
}

// validVia: where a route sends traffic (empty for old journals).
func validVia(s string) bool {
	return s == "" || s == "corp" || s == "home" || s == "direct"
}

// ValidateRoute checks a journal entry before anything is executed for it.
func ValidateRoute(r Route) error {
	if _, err := ParseCIDR4(r.Dest); err != nil {
		return fmt.Errorf("route destination: %w", err)
	}
	if !ValidIface(r.Iface) {
		return fmt.Errorf("route %s: invalid adapter name", r.Dest)
	}
	if r.Gateway != "" {
		if _, err := ParseIPv4(r.Gateway); err != nil {
			return fmt.Errorf("route %s gateway: %w", r.Dest, err)
		}
	}
	if !validVia(r.Via) {
		return fmt.Errorf("route %s: unknown direction %q", r.Dest, clip(r.Via))
	}
	return nil
}

// ValidateServers checks a list of DNS server addresses (IPv4 only).
func ValidateServers(servers []string) error {
	for _, s := range servers {
		if _, err := ParseIPv4(s); err != nil {
			return fmt.Errorf("DNS server: %w", err)
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// Sanitize validates every field of c as loaded from disk, dropping what is
// invalid, and returns a warning for each dropped or fixed value. The file
// belongs to a user, but it is read by a process with administrator rights.
func (c *Config) Sanitize() (warnings []string) {
	warn := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	sel := func(name, v, def string) string {
		if v == "" {
			return def
		}
		if !ValidIface(v) {
			warn("config: invalid %s %q, using %q", name, clip(v), def)
			return def
		}
		return v
	}
	c.Corp = sel("corp_iface", c.Corp, "auto")
	c.Home = sel("home_iface", c.Home, "auto")
	for _, f := range []struct {
		name string
		p    *string
	}{{"corp_gateway", &c.CorpGateway}, {"corp_dns", &c.CorpDNS}} {
		if *f.p == "" {
			continue
		}
		ip, err := ParseIPv4(*f.p)
		if err != nil {
			warn("config: %s dropped: %v", f.name, err)
			ip = ""
		}
		*f.p = ip
	}
	clean := func(name string, list []string, wantNet bool) []string {
		var out []string
		for _, r := range list {
			isNet, v, err := NormalizeRule(r)
			switch {
			case err != nil:
				warn("config: %s: rule %q dropped: %v", name, clip(r), err)
			case isNet != wantNet:
				warn("config: %s: rule %q is in the wrong list, dropped", name, clip(r))
			default:
				out = AddUnique(out, v)
			}
		}
		return out
	}
	c.Networks = clean("networks", c.Networks, true)
	c.Domains = clean("domains", c.Domains, false)
	c.DirectNetworks = clean("direct_networks", c.DirectNetworks, true)
	c.DirectDomains = clean("direct_domains", c.DirectDomains, false)
	// the file on disk still has what was dropped; Save keeps a copy of it
	c.lossy = len(warnings) > 0
	return warnings
}

// ParseBool understands the yes/no spellings the CLI accepts; anything else
// is an error instead of a silent "false".
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1", "да", "on":
		return true, nil
	case "false", "no", "0", "нет", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a yes/no value (use true/yes/1/да/on or false/no/0/нет/off)", clip(s))
}
