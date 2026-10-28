package clientcfg

import (
	"encoding/json"
	"errors"
	"strings"
)

// ParseSingBox reads the parts of a sing-box configuration (JSON, the format
// Hiddify generates too) that matter here: tun inbounds with strict_route, and
// the fake-ip DNS (the "dns.fakeip" block of sing-box before 1.12, servers of
// type "fakeip" after) with its inet4_range. Anything else is ignored; a text
// that is not a JSON object is an error. Values of unexpected types count as
// absent.
func ParseSingBox(data []byte) (TunCfg, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return TunCfg{}, err
	}
	if root == nil {
		return TunCfg{}, errors.New("not an object")
	}
	var c TunCfg
	for _, in := range asList(root["inbounds"]) {
		m, ok := in.(map[string]any)
		if !ok || str(m["type"]) != "tun" {
			continue
		}
		c.Tun = true
		if b, _ := m["strict_route"].(bool); b {
			c.StrictRoute = true
		}
	}
	dns, _ := root["dns"].(map[string]any)
	if dns == nil {
		return c, nil
	}
	if fi, ok := dns["fakeip"].(map[string]any); ok {
		if on, _ := fi["enabled"].(bool); on {
			c.FakeIP = true
			c.addRange(fi["inet4_range"])
		}
	}
	for _, s := range asList(dns["servers"]) {
		if m, ok := s.(map[string]any); ok && str(m["type"]) == "fakeip" {
			c.FakeIP = true
			c.addRange(m["inet4_range"])
		}
	}
	return c, nil
}

// addRange adds the range v when it is a valid IPv4 fake-ip range.
func (c *TunCfg) addRange(v any) {
	s := str(v)
	if s == "" {
		return
	}
	p, ok := parseFakeRange(s)
	if !ok {
		return
	}
	for _, have := range c.FakeRanges {
		if have == p {
			return
		}
	}
	if len(c.FakeRanges) < MaxFakeRanges {
		c.FakeRanges = append(c.FakeRanges, p)
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
