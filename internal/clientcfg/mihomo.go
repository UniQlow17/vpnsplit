package clientcfg

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

// maxYAMLLines bounds how many lines of a Mihomo (Clash) config are looked at.
const maxYAMLLines = 200000

// ParseMihomo reads the keys of a Mihomo / Clash.Meta config (YAML) that
// matter here: tun.enable, tun.strict-route, dns.enable, dns.enhanced-mode and
// dns.fake-ip-range. It is not a YAML parser: the file is a list of lines with
// indentation, and only the direct children of the top-level sections "tun" and
// "dns" are taken, in the block form ("key: value" lines) and in the one-line
// flow form ("tun: {enable: true, strict-route: true}"). Anchors, tags and
// multi-line scalars are not understood; that only means a key is not found.
// Binary data or a tab in the indentation make the text "not YAML" (an error),
// which the callers treat as "nothing known". The first occurrence of a key wins.
func ParseMihomo(data []byte) (TunCfg, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return TunCfg{}, errors.New("binary data")
	}
	tun, dns := map[string]string{}, map[string]string{}
	var cur map[string]string // the section the lines belong to; nil: another section
	childIndent := -1
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 0; sc.Scan(); n++ {
		if n >= maxYAMLLines {
			break
		}
		line := strings.TrimRight(stripComment(sc.Text()), " \r")
		if strings.TrimSpace(line) == "" || line == "---" || line == "..." {
			continue
		}
		if strings.ContainsRune(leadingSpace(line), '\t') {
			return TunCfg{}, errors.New("tab in the indentation")
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, val, ok := splitKey(line[indent:])
		if !ok {
			continue
		}
		if indent == 0 {
			cur, childIndent = nil, -1
			var dst map[string]string
			switch key {
			case "tun":
				dst = tun
			case "dns":
				dst = dns
			default:
				continue
			}
			if strings.HasPrefix(val, "{") {
				flowPairs(val, dst)
				continue
			}
			cur = dst
			continue
		}
		if cur == nil {
			continue
		}
		if childIndent < 0 {
			childIndent = indent
		}
		if indent == childIndent {
			if _, dup := cur[key]; !dup {
				cur[key] = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return TunCfg{}, err
	}
	var c TunCfg
	if isTrue(tun["enable"]) {
		c.Tun = true
		c.StrictRoute = isTrue(tun["strict-route"])
	}
	// the DNS section of Mihomo is off unless dns.enable is true: then enhanced-mode means nothing
	if isTrue(dns["enable"]) && strings.EqualFold(trimQuotes(dns["enhanced-mode"]), "fake-ip") {
		c.FakeIP = true
		if p, ok := parseFakeRange(dns["fake-ip-range"]); ok {
			c.FakeRanges = append(c.FakeRanges, p)
		}
	}
	return c, nil
}

func leadingSpace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// stripComment removes "# ..." that starts a comment: at the start of the
// line or after a space, outside of quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// splitKey splits "key: value" ("key:" has an empty value). Lines of lists
// and the like (no key) are not ok.
func splitKey(s string) (key, val string, ok bool) {
	if strings.HasPrefix(s, "- ") || s == "-" {
		return "", "", false
	}
	i := -1
	for j := 0; j < len(s); j++ {
		if s[j] == ':' && (j+1 == len(s) || s[j+1] == ' ') {
			i = j
			break
		}
	}
	if i <= 0 {
		return "", "", false
	}
	key = trimQuotes(strings.TrimSpace(s[:i]))
	if key == "" {
		return "", "", false
	}
	return key, strings.TrimSpace(s[i+1:]), true
}

// flowPairs reads "{a: 1, b: x}" into dst (simple scalars only).
func flowPairs(v string, dst map[string]string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "{")
	if i := strings.LastIndex(v, "}"); i >= 0 {
		v = v[:i]
	}
	for _, part := range strings.Split(v, ",") {
		if k, val, ok := splitKey(strings.TrimSpace(part)); ok {
			if _, dup := dst[k]; !dup {
				dst[k] = val
			}
		}
	}
}

func isTrue(v string) bool {
	switch strings.ToLower(trimQuotes(strings.TrimSpace(v))) {
	case "true", "yes", "on":
		return true
	}
	return false
}
