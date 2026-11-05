//go:build linux

package sysproc

import "testing"

func TestParseStatStart(t *testing.T) {
	// the command name has spaces and a parenthesis
	s := "1234 (my (weird) cmd) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	got, err := parseStatStart(s)
	if err != nil || got != 987654 {
		t.Errorf("%d %v", got, err)
	}
	if _, err := parseStatStart("garbage"); err == nil {
		t.Error("garbage must fail")
	}
}
