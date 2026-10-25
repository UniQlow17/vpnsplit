package config

import (
	"strings"
	"testing"
)

func TestNormalizeRule(t *testing.T) {
	tests := []struct {
		in      string
		isNet   bool
		want    string
		wantErr bool
	}{
		{"10.0.0.0/8", true, "10.0.0.0/8", false},
		{"10.1.2.3/8", true, "10.0.0.0/8", false},
		{"192.168.1.5", true, "192.168.1.5/32", false},
		{"  Intra.Example.COM ", false, "intra.example.com", false},
		{"*.example.com", false, "example.com", false},
		{"fd00::/8", false, "", true},
		{"::1", false, "", true},
		{"localhost", false, "", true},
		{"a b.com", false, "", true},
		{"", false, "", true},
		{"AS15632", true, "AS15632", false},
		{" as049675 ", true, "AS49675", false},
		{"as", false, "", true},
		{"asdf.example.com", false, "asdf.example.com", false},
	}
	for _, tt := range tests {
		isNet, got, err := NormalizeRule(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && (isNet != tt.isNet || got != tt.want) {
			t.Errorf("%q: got (%v, %q), want (%v, %q)", tt.in, isNet, got, tt.isNet, tt.want)
		}
	}
}

func TestAddRemove(t *testing.T) {
	l := AddUnique(nil, "a")
	l = AddUnique(l, "a")
	l = AddUnique(l, "b")
	if len(l) != 2 {
		t.Fatalf("AddUnique: got %v", l)
	}
	l, ok := RemoveVal(l, "a")
	if !ok || len(l) != 1 || l[0] != "b" {
		t.Fatalf("RemoveVal: got %v, %v", l, ok)
	}
	if _, ok := RemoveVal(l, "zzz"); ok {
		t.Fatal("RemoveVal reported a missing value as found")
	}
}

func TestImportExportRules(t *testing.T) {
	c := New()
	c.DirectNetworks = []string{"46.17.200.0/21"}
	added, errs := c.ImportRules(`# shared list
10.0.0.0/8            # no section yet: corp
[DIRECT]
46.17.200.0/21        # already there
217.12.104.0/23
telework.example.ru
not a rule
[corp]
intranet.example.com
`)
	if added != 4 {
		t.Errorf("added %d, want 4", added)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "line 7") {
		t.Errorf("errs %v, want one for line 7", errs)
	}
	if len(c.Networks) != 1 || len(c.Domains) != 1 || len(c.DirectNetworks) != 2 || len(c.DirectDomains) != 1 {
		t.Errorf("got corp %v %v direct %v %v", c.Networks, c.Domains, c.DirectNetworks, c.DirectDomains)
	}

	again := New()
	if n, errs := again.ImportRules(c.ExportRules()); n != 5 || len(errs) != 0 {
		t.Errorf("round trip: %d rules, errs %v", n, errs)
	}
}
