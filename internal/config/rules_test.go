package config

import "testing"

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
