package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	snapshotFile = "snapshot.json"
	planFile     = "plan.json"

	// MaxSnapRoutes bounds the routes a snapshot holds: a table larger than that
	// is not kept, and the comparison with it is only a report.
	MaxSnapRoutes = 200_000
	// SnapshotTTL is how long a snapshot of an unknown boot stays believable.
	SnapshotTTL = 7 * 24 * time.Hour
)

// SnapRoute is one IPv4 route of the table as it was when the snapshot was taken.
type SnapRoute struct {
	Dest    string `json:"dest"`
	Iface   string `json:"iface,omitempty"`
	IfIndex int    `json:"ifindex,omitempty"` // for the eye: a reconnected adapter has another one
	LUID    uint64 `json:"luid,omitempty"`    // Windows
	Gateway string `json:"gateway,omitempty"`
	Metric  int    `json:"metric"`
	Table   int    `json:"table,omitempty"` // Linux: 0 is the main table
	Proto   int    `json:"proto,omitempty"` // Linux: rtm_protocol; Windows: NL_ROUTE_PROTOCOL
	Origin  int    `json:"origin,omitempty"`
}

// SnapRule is one policy rule (Linux).
type SnapRule struct {
	Pref     int    `json:"pref"`
	Table    int    `json:"table"`
	Src      string `json:"src,omitempty"`
	Dest     string `json:"dest,omitempty"`
	Suppress int    `json:"suppress"`
	ToTable  bool   `json:"to_table,omitempty"`
	Fwmark   bool   `json:"fwmark,omitempty"`
	Inv      bool   `json:"inv,omitempty"`
	Other    bool   `json:"other,omitempty"`
}

// SnapResolver is one per-domain DNS entry that was there (Windows: an NRPT
// rule, macOS: a file of /etc/resolver).
type SnapResolver struct {
	ID     string `json:"id"`               // the zone (Windows) or the path (macOS)
	Detail string `json:"detail,omitempty"` // name servers and the comment of the rule
	Ours   bool   `json:"ours,omitempty"`   // carried our mark at that time (a leftover of ours)
}

// Snapshot is what the system looked like before vpnsplit changed anything:
// the baseline that the end of a session compares the system with. It lives
// next to the journal, in the protected directory, and belongs to one run of
// the computer (Owner.Boot): after a restart routes are not what they were.
type Snapshot struct {
	Version int    `json:"version"`
	Owner   *Owner `json:"owner,omitempty"` // the process that took it
	Taken   string `json:"taken,omitempty"` // RFC 3339
	// Approx: taken while the journal still listed entries (a persistent
	// apply, a dead session's leftovers); what the journal lists was left out.
	Approx bool `json:"approx,omitempty"`

	RoutesKnown    bool           `json:"routes_known"`
	Routes         []SnapRoute    `json:"routes,omitempty"`
	RulesKnown     bool           `json:"rules_known"`
	Rules          []SnapRule     `json:"rules,omitempty"`
	ResolversKnown bool           `json:"resolvers_known"`
	Resolvers      []SnapResolver `json:"resolvers,omitempty"`

	// ReportOnly: the comparison with this snapshot may only report, never
	// remove (the table was too large to keep, or the file had entries that made
	// no sense). Why says which.
	ReportOnly bool   `json:"report_only,omitempty"`
	Why        string `json:"why,omitempty"`
}

// PlanNotes is every route (destination|adapter|next hop|table) vpnsplit has
// planned since the snapshot Taken was made, and Kept the ones it found
// already there and left alone as somebody else's. A route that carries our
// mark is told from a VPN client's by the first and never by the second (see
// router.baseline). It lives in a file of its own: it grows while the
// snapshot, which can be large, does not change.
type PlanNotes struct {
	Taken   string   `json:"taken"`
	Planned []string `json:"planned,omitempty"`
	Kept    []string `json:"kept,omitempty"`
}

// SnapState is what is known about whether a snapshot describes the system
// of this boot.
type SnapState int

const (
	// SnapInvalid: it is from another boot (or has no owner): the table it
	// describes is gone.
	SnapInvalid SnapState = iota
	// SnapProven: it was taken by this very process, or the boot ids on both
	// sides are known and equal, or the age proves it.
	SnapProven
	// SnapUnproven: the boot id is unknown on one side and the age does not
	// prove anything. The comparison may report but must not remove.
	SnapUnproven
)

// bootTolerance: the boot time is derived from the clock, which is corrected
// after the boot (see sysproc).
const bootTolerance = 10 * time.Minute

// Validity tells whether the snapshot may be compared with the system of the
// boot self belongs to. sameBoot is sysproc.SameBoot (an unknown id on either
// side is "same", which proves nothing, so it is not asked then). With an
// unknown id, only the age can prove anything: the snapshot must be younger
// than SnapshotTTL and not older than the boot (self.Boot as unix seconds, where
// the OS gives the boot time).
func (s *Snapshot) Validity(self Owner, sameBoot func(a, b string) bool, now time.Time) SnapState {
	if s == nil || s.Owner == nil {
		return SnapInvalid
	}
	if s.Owner.PID == self.PID && s.Owner.Start == self.Start && self.Start != 0 {
		return SnapProven // our own, made a moment ago
	}
	if s.Owner.Boot != "" && self.Boot != "" {
		if sameBoot(s.Owner.Boot, self.Boot) {
			return SnapProven
		}
		return SnapInvalid
	}
	taken, err := time.Parse(time.RFC3339, s.Taken)
	if err != nil || taken.After(now.Add(bootTolerance)) || now.Sub(taken) > SnapshotTTL {
		return SnapUnproven
	}
	if secs, err := strconv.ParseInt(self.Boot, 10, 64); err == nil && secs > 0 {
		if taken.Before(time.Unix(secs, 0).Add(-bootTolerance)) {
			return SnapInvalid // made before this boot
		}
		return SnapProven
	}
	return SnapUnproven
}

// SaveSnapshot writes the snapshot atomically into the protected directory.
func SaveSnapshot(s *Snapshot) error {
	dir, err := StateDir(true)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return saveSnapshotIn(dir, s)
}

func saveSnapshotIn(dir string, s *Snapshot) error {
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Taken == "" {
		s.Taken = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, snapshotFile, b, 0o600, nil)
}

// LoadSnapshot returns the snapshot; nil with no error if there is none. A
// file that cannot be parsed is an error (and is left alone).
func LoadSnapshot() (*Snapshot, error) {
	dir, err := StateDir(false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadSnapshotIn(dir)
}

func loadSnapshotIn(dir string) (*Snapshot, error) {
	b, err := readRegular(filepath.Join(dir, snapshotFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	s := &Snapshot{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	s.Sanitize()
	return s, nil
}

// SafeText reports whether s may be shown and compared: valid UTF-8, no
// control characters, bounded length.
func SafeText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

// Sanitize drops what could not have been written by this tool (the file is
// read with administrator rights, and its text ends up on screen). When
// something is dropped the snapshot becomes ReportOnly: the system would look
// different from it for no reason of its own.
func (s *Snapshot) Sanitize() {
	dropped := 0
	routes := s.Routes[:0]
	for _, r := range s.Routes {
		ok := SafeText(r.Iface, 256) && r.Metric >= 0 && r.Metric <= 1<<20 && r.Table >= 0 && r.Table <= 1<<24 &&
			r.Proto >= 0 && r.Proto <= 255 && r.Origin >= 0 && r.Origin <= 255
		p, perr := netip.ParsePrefix(r.Dest)
		if perr != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			ok = false
		}
		if r.Gateway != "" {
			// the next hop is of the family of the destination
			if a, err := netip.ParseAddr(r.Gateway); err != nil || a.Is4In6() || a.Zone() != "" || perr != nil || a.Is4() != p.Addr().Is4() {
				ok = false
			}
		}
		if !ok {
			dropped++
			continue
		}
		routes = append(routes, r)
	}
	s.Routes = routes
	rules := s.Rules[:0]
	for _, r := range s.Rules {
		ok := r.Pref >= 0 && r.Pref <= 1<<31-1 && r.Table >= 0 && r.Table <= 1<<31-1 && r.Suppress >= -1
		for _, x := range []string{r.Src, r.Dest} {
			if x != "" {
				if _, err := netip.ParsePrefix(x); err != nil {
					ok = false
				}
			}
		}
		if !ok {
			dropped++
			continue
		}
		rules = append(rules, r)
	}
	s.Rules = rules
	res := s.Resolvers[:0]
	for _, r := range s.Resolvers {
		if r.ID == "" || !SafeText(r.ID, 512) || !SafeText(r.Detail, 4096) {
			dropped++
			continue
		}
		res = append(res, r)
	}
	s.Resolvers = res
	if !SafeText(s.Taken, 64) {
		s.Taken = ""
	}
	if o := s.Owner; o != nil && (o.PID <= 0 || o.Start < 0 || !SafeText(o.Boot, 64)) {
		s.Owner = nil
	}
	if !SafeText(s.Why, 256) {
		s.Why = ""
	}
	if dropped > 0 {
		s.ReportOnly = true
		if s.Why == "" {
			s.Why = fmt.Sprintf("%d entries of the snapshot were unreadable", dropped)
		}
	}
}

// RemoveSnapshot deletes the snapshot and the notes of the plans; none is no error.
func RemoveSnapshot() error {
	dir, err := StateDir(false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return removeSnapshotIn(dir)
}

func removeSnapshotIn(dir string) error {
	err := removeRegular(dir, snapshotFile)
	if perr := removeRegular(dir, planFile); err == nil {
		err = perr
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

// SavePlanNotes writes the notes of the plans next to the snapshot.
func SavePlanNotes(n *PlanNotes) error {
	dir, err := StateDir(true)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return savePlanNotesIn(dir, n)
}

func savePlanNotesIn(dir string, n *PlanNotes) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, planFile, b, 0o600, nil)
}

// LoadPlanNotes returns the notes made since the snapshot Taken; nil if there
// are none, or they belong to another snapshot.
func LoadPlanNotes(taken string) (*PlanNotes, error) {
	dir, err := StateDir(false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadPlanNotesIn(dir, taken)
}

func loadPlanNotesIn(dir, taken string) (*PlanNotes, error) {
	b, err := readRegular(filepath.Join(dir, planFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	n := &PlanNotes{}
	if err := json.Unmarshal(b, n); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if n.Taken != taken {
		return nil, nil // left by an earlier snapshot
	}
	clean := func(in []string) []string {
		var out []string
		for _, d := range in {
			if d != "" && SafeText(d, 1024) {
				out = append(out, d)
			}
		}
		return out
	}
	n.Planned, n.Kept = clean(n.Planned), clean(n.Kept)
	return n, nil
}
