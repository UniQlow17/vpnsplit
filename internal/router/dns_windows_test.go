//go:build windows

package router

import (
	"strings"
	"testing"
)

const payload = "a.x’}|out-null;calc;get-dnsclientnrptrule|?{’"

// Values reach PowerShell only through the environment, so they come back
// byte for byte and are never executed. The script only prints the variable.
func TestPSPassesDataVerbatim(t *testing.T) {
	for _, v := range []string{payload, "it's", "a‘b‚c‛d", `a"b`, "$(calc)", "`n", "Беспроводная сеть", "a;b|c&d"} {
		out, err := ps(map[string]string{"X": v}, "[Console]::Out.Write($env:VS_X)")
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if string(out) != v {
			t.Errorf("got %q, want %q", out, v)
		}
	}
}

// Invalid data is rejected before any PowerShell process is started.
func TestResolverRejectsInvalidInput(t *testing.T) {
	if err := addResolver(payload, []string{"10.0.0.1"}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("addResolver: %v", err)
	}
	if err := addResolver("corp.example.com", []string{"10.0.0.1'; calc; '"}); err == nil {
		t.Error("addResolver accepted a bad server")
	}
	if err := delResolver(payload); err == nil {
		t.Error("delResolver accepted a bad zone")
	}
}

func TestRouteRejectsInvalidInput(t *testing.T) {
	r := routeFor("1.2.3.4'; calc; '")
	if err := addRoute(r); err == nil {
		t.Error("addRoute accepted a bad gateway")
	}
	if err := delRoute(r); err == nil {
		t.Error("delRoute accepted a bad gateway")
	}
}
