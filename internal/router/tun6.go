package router

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The automatic IPv6 tunnelling of Windows (Teredo, 6to4, ISATAP) wraps IPv6 in
// IPv4 and sends it out of the physical adapter by itself, around the home VPN.
// While the rest of the traffic goes into the home VPN these are turned off, and
// what each was is put back at the end (the journal holds the original).

// disableTun6 says what is to be put back (orig: the settings that are not
// "Disabled" yet, in the spelling of the cmdlets) and what is to be set now
// (set: "Disabled" for each of them). A value that is not a known one is left
// alone: nothing unexpected is ever handed back to a cmdlet.
func disableTun6(cur config.Tunnels6) (orig, set config.Tunnels6) {
	if v, ok := config.CanonTeredo(cur.Teredo); ok && v != "Disabled" {
		orig.Teredo, set.Teredo = v, "Disabled"
	}
	if v, ok := config.CanonSixToFour(cur.SixToFour); ok && v != "Disabled" {
		orig.SixToFour, set.SixToFour = v, "Disabled"
	}
	if v, ok := config.CanonISATAP(cur.ISATAP); ok && v != "Disabled" {
		orig.ISATAP, set.ISATAP = v, "Disabled"
	}
	return orig, set
}

// warnUnknownTun6 reports the settings that have a value this tool does not
// know: they are left as they are, and the IPv6 may still go around the tunnel
// through them.
func warnUnknownTun6(w io.Writer, unknown []string) {
	if len(unknown) > 0 {
		fmt.Fprintf(w, "  ! IPv6 tunnels: setting(s) with a value unknown to vpnsplit left as they are: %s\n", strings.Join(unknown, ", "))
	}
}

// onlyRecorded keeps of set the settings that have an original in the journal
// (rec): what was not recorded was not ours to turn off.
func onlyRecorded(set, rec config.Tunnels6) config.Tunnels6 {
	if rec.Teredo == "" {
		set.Teredo = ""
	}
	if rec.SixToFour == "" {
		set.SixToFour = ""
	}
	if rec.ISATAP == "" {
		set.ISATAP = ""
	}
	return set
}

// checkTun6 validates the settings before they reach a cmdlet and returns them
// in canonical form; an empty field stays empty (not touched).
func checkTun6(t config.Tunnels6) (config.Tunnels6, error) {
	c := t
	if c.Sanitize() != 0 {
		return config.Tunnels6{}, errTun6
	}
	return c, nil
}

type tun6Error string

func (e tun6Error) Error() string { return string(e) }

const errTun6 = tun6Error("unexpected value of an IPv6 tunnel setting")

// describeTun6 is the settings as text (for the report).
func describeTun6(t *config.Tunnels6) string {
	if t.Empty() {
		return ""
	}
	var parts []string
	if t.Teredo != "" {
		parts = append(parts, "Teredo "+t.Teredo)
	}
	if t.SixToFour != "" {
		parts = append(parts, "6to4 "+t.SixToFour)
	}
	if t.ISATAP != "" {
		parts = append(parts, "ISATAP "+t.ISATAP)
	}
	return strings.Join(parts, ", ")
}

// restoreTun6 puts the settings of the journal back: the values are validated
// first, and the call is abandoned when ctx ends (the journal then keeps them).
func (m *Manager) restoreTun6(ctx context.Context, t config.Tunnels6) error {
	t6, ok := m.b.(tunnels6)
	if !ok {
		return nil // nothing was changed here: the journal is from a machine of another kind
	}
	c, err := checkTun6(t)
	if err != nil {
		return err
	}
	return runAll(ctx, []struct{}{{}}, 1, func(struct{}) error { return t6.SetTunnels6(c) })[0]
}
