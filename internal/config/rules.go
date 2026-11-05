package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// NormalizeRule classifies input as a network (isNet: IPv4 CIDR, IP, or an
// autonomous system "AS49675" that stands for all its networks) or a domain,
// and returns its canonical form. Domains must be ASCII (punycode for
// internationalized names) and pass ValidDomain.
func NormalizeRule(s string) (isNet bool, val string, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return false, "", fmt.Errorf("empty rule")
	}
	if n, ok := strings.CutPrefix(s, "as"); ok && n != "" && strings.Trim(n, "0123456789") == "" {
		if n = strings.TrimLeft(n, "0"); n == "" {
			return false, "", fmt.Errorf("AS0 is not a real autonomous system")
		}
		if as := "AS" + n; ValidAS(as) {
			return true, as, nil
		}
		return false, "", fmt.Errorf("%q is not a valid AS number", clip(s))
	}
	if p, e := netip.ParsePrefix(s); e == nil {
		if !p.Addr().Is4() {
			return false, "", fmt.Errorf("%s: only IPv4 is supported", clip(s))
		}
		return true, p.Masked().String(), nil
	}
	if a, e := netip.ParseAddr(s); e == nil {
		if !a.Is4() {
			return false, "", fmt.Errorf("%s: only IPv4 is supported", clip(s))
		}
		return true, a.String() + "/32", nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")
	if last := s[strings.LastIndex(s, ".")+1:]; !strings.Contains(s, ".") || !ValidZone(s) || strings.Trim(last, "0123456789") == "" {
		return false, "", fmt.Errorf("%q is neither a CIDR/IP nor a domain (ASCII letters, digits, '-', '_' and '.'; for non-ASCII names use punycode, e.g. xn--e1afmkfd.xn--p1ai)", clip(s))
	}
	return false, s, nil
}

// IsAS reports whether a network rule is an autonomous system ("AS49675").
func IsAS(rule string) bool { return strings.HasPrefix(rule, "AS") }

// AddUnique appends v unless it is already present.
func AddUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// RemoveVal returns list without v and whether v was present.
func RemoveVal(list []string, v string) ([]string, bool) {
	var out []string
	found := false
	for _, x := range list {
		if x == v {
			found = true
			continue
		}
		out = append(out, x)
	}
	return out, found
}
