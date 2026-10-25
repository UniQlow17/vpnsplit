package config

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeRule classifies input as a network (isNet: IPv4 CIDR, IP, or an
// autonomous system "AS49675" that stands for all its networks) or a domain,
// and returns its canonical form.
func NormalizeRule(s string) (isNet bool, val string, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return false, "", fmt.Errorf("empty rule")
	}
	if n, ok := strings.CutPrefix(s, "as"); ok && n != "" && strings.Trim(n, "0123456789") == "" {
		if n = strings.TrimLeft(n, "0"); n == "" {
			return false, "", fmt.Errorf("AS0 is not a real autonomous system")
		}
		return true, "AS" + n, nil
	}
	if _, n, e := net.ParseCIDR(s); e == nil {
		if n.IP.To4() == nil {
			return false, "", fmt.Errorf("%s: only IPv4 is supported", s)
		}
		return true, n.String(), nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() == nil {
			return false, "", fmt.Errorf("%s: only IPv4 is supported", s)
		}
		return true, ip.String() + "/32", nil
	}
	s = strings.TrimPrefix(s, "*.")
	if strings.ContainsAny(s, " /\\:") || !strings.Contains(s, ".") {
		return false, "", fmt.Errorf("%q is neither a CIDR/IP nor a domain", s)
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
