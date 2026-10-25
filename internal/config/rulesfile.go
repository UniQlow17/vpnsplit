package config

import (
	"fmt"
	"strings"
)

// A rules file is plain text that people pass around:
//
//	# comment
//	[direct]           rules below go past every VPN
//	217.12.96.0/21
//	[corp]             rules below go through the corp VPN
//	intranet.example.com
//
// Rules before any section go to corp, like `vpnsplit add`.

// ImportRules adds the rules of a rules file to c and reports how many were
// new. Lines that are not rules are returned as errors with their numbers and
// do not stop the import.
func (c *Config) ImportRules(text string) (added int, errs []error) {
	direct := false
	for n, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "":
			continue
		case "[direct]":
			direct = true
			continue
		case "[corp]":
			direct = false
			continue
		}
		isNet, v, err := NormalizeRule(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %v", n+1, err))
			continue
		}
		nets, domains := c.Lists(direct)
		list := domains
		if isNet {
			list = nets
		}
		before := len(*list)
		if *list = AddUnique(*list, v); len(*list) > before {
			added++
		}
	}
	return added, errs
}

// ExportRules writes the rules of c as a rules file.
func (c *Config) ExportRules() string {
	var b strings.Builder
	b.WriteString("# vpnsplit rules: import with `vpnsplit import <file>` or Rules → Import in the menu\n")
	for _, s := range []struct {
		head          string
		nets, domains []string
	}{
		{"[direct]", c.DirectNetworks, c.DirectDomains},
		{"[corp]", c.Networks, c.Domains},
	} {
		if len(s.nets)+len(s.domains) == 0 {
			continue
		}
		b.WriteString("\n" + s.head + "\n")
		for _, r := range append(append([]string{}, s.nets...), s.domains...) {
			b.WriteString(r + "\n")
		}
	}
	return b.String()
}
