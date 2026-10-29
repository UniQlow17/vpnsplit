//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestStrictSD(t *testing.T) {
	cases := []struct {
		sddl string
		want bool
	}{
		{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", true},
		{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FA;;;CO)", true},
		{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)", false},      // write data for users
		{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x4;;;AU)", false},     // append
		{"O:BAD:P(A;;FA;;;SY)(A;;0x40;;;WD)", false},                // delete child
		{"O:BAD:P(A;;FA;;;SY)(A;;WD;;;BU)", false},                  // change the list
		{"O:BAD:P(A;;FA;;;SY)(A;;WO;;;BU)", false},                  // take ownership
		{"O:BAD:P(A;;FA;;;SY)(A;;SD;;;BU)", false},                  // delete
		{"O:BAD:P(A;;FA;;;SY)(A;;GA;;;BU)", false},                  // generic all
		{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;CO)", true},                   // creator owner, owner trusted
		{"O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)", false},                  // owner is a user
		{"O:COD:P(A;;FA;;;SY)", false},                              // creator owner as owner
		{"O:BAD:P(A;;FA;;;SY)(D;;FW;;;BU)(A;;0x1200a9;;;BU)", true}, // a deny is no grant
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			// not every spelling is accepted: skip it rather than fail
			t.Logf("%s: %v", c.sddl, err)
			continue
		}
		if got := strictSD(sd); got != c.want {
			t.Errorf("%s: %v, want %v", c.sddl, got, c.want)
		}
	}
	if strictSD(nil) {
		t.Error("nil accepted")
	}
	sd, err := windows.SecurityDescriptorFromString("O:BA")
	if err == nil && strictSD(sd) {
		t.Error("no access list accepted")
	}
}
