package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSnapshotRoundTripAndRemove(t *testing.T) {
	dir := t.TempDir()
	if s, err := loadSnapshotIn(dir); s != nil || err != nil {
		t.Fatalf("no file yet: %v %v", s, err)
	}
	in := &Snapshot{Owner: &Owner{PID: 7, Boot: "b1"}, RoutesKnown: true,
		Routes: []SnapRoute{{Dest: "10.0.0.0/8", Iface: "tun0", IfIndex: 9, LUID: 1 << 40, Gateway: "10.0.0.1", Metric: 25, Proto: 3}},
		Rules:  []SnapRule{{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}}}
	if err := saveSnapshotIn(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := loadSnapshotIn(dir)
	if err != nil || out == nil {
		t.Fatal(out, err)
	}
	if out.Version != 1 || out.Taken == "" || len(out.Routes) != 1 || out.Routes[0].LUID != 1<<40 ||
		out.Rules[0].Pref != 9000 || out.Owner.Boot != "b1" || out.ReportOnly {
		t.Errorf("%+v", out)
	}
	if fi, err := os.Stat(filepath.Join(dir, snapshotFile)); err != nil || fi.Mode().Perm()&0o077 != 0 && !isWindowsMode() {
		t.Errorf("the snapshot must be private: %v %v", fi, err)
	}
	if err := removeSnapshotIn(dir); err != nil {
		t.Fatal(err)
	}
	if s, _ := loadSnapshotIn(dir); s != nil {
		t.Error("not removed")
	}
	if err := removeSnapshotIn(dir); err != nil {
		t.Errorf("removing nothing is no error: %v", err)
	}
}

func isWindowsMode() bool { return runtime.GOOS == "windows" }

func TestSnapshotBrokenFileIsAnErrorNotEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := loadSnapshotIn(dir); s != nil || err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("%v %v", s, err)
	}
}

// A snapshot belongs to one boot of the computer: after a restart the table it
// describes is gone. With an unknown boot id only the age can prove anything.
func TestSnapshotValidity(t *testing.T) {
	same := func(a, b string) bool { return a == "" || b == "" || a == b }
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	self := Owner{PID: 5, Start: 50, Boot: "b1"}
	boot := func(ago time.Duration) string { return strconv.FormatInt(now.Add(-ago).Unix(), 10) }
	cases := []struct {
		name string
		s    *Snapshot
		self Owner
		want SnapState
	}{
		{"same boot", &Snapshot{Owner: &Owner{PID: 1, Boot: "b1"}}, self, SnapProven},
		{"other boot", &Snapshot{Owner: &Owner{PID: 1, Boot: "b0"}}, self, SnapInvalid},
		{"no snapshot", nil, self, SnapInvalid},
		{"no owner", &Snapshot{}, self, SnapInvalid},
		{"made by this very process", &Snapshot{Owner: &Owner{PID: 5, Start: 50}, Taken: at(time.Hour)}, Owner{PID: 5, Start: 50}, SnapProven},
		{"unknown id, no boot time: nothing proves it", &Snapshot{Owner: &Owner{PID: 1}, Taken: at(time.Hour)}, Owner{PID: 9, Start: 9}, SnapUnproven},
		{"unknown id of the snapshot, boot time known, taken after boot", &Snapshot{Owner: &Owner{PID: 1}, Taken: at(time.Hour)}, Owner{PID: 9, Boot: boot(48 * time.Hour)}, SnapProven},
		{"unknown id, taken before the boot", &Snapshot{Owner: &Owner{PID: 1}, Taken: at(72 * time.Hour)}, Owner{PID: 9, Boot: boot(48 * time.Hour)}, SnapInvalid},
		{"unknown id, older than the TTL", &Snapshot{Owner: &Owner{PID: 1}, Taken: at(8 * 24 * time.Hour)}, Owner{PID: 9, Boot: boot(30 * 24 * time.Hour)}, SnapUnproven},
		{"unknown id, no time taken", &Snapshot{Owner: &Owner{PID: 1}}, Owner{PID: 9, Boot: boot(time.Hour)}, SnapUnproven},
		{"own id unknown, snapshot has one", &Snapshot{Owner: &Owner{PID: 1, Boot: "b1"}, Taken: at(time.Hour)}, Owner{PID: 9}, SnapUnproven},
	}
	for _, c := range cases {
		if got := c.s.Validity(c.self, same, now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSnapshotSanitize(t *testing.T) {
	dir := t.TempDir()
	in := &Snapshot{Owner: &Owner{PID: 3, Boot: "b"}, RoutesKnown: true, ResolversKnown: true,
		Routes: []SnapRoute{
			{Dest: "10.0.0.0/8", Iface: "ok", Gateway: "10.0.0.1", Metric: 5},
			{Dest: "not-a-prefix", Iface: "x"},
			{Dest: "10.1.0.0/16", Iface: "bad\x1b[31mname"},
			{Dest: "10.2.0.0/16", Iface: "x", Gateway: "::1"},
			{Dest: "10.3.0.0/16", Iface: "x", Metric: -4},
		},
		Resolvers: []SnapResolver{{ID: "a.example", Detail: "ok"}, {ID: "b\n.example"}}}
	if err := saveSnapshotIn(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := loadSnapshotIn(dir)
	if err != nil || out == nil {
		t.Fatal(out, err)
	}
	if len(out.Routes) != 1 || out.Routes[0].Dest != "10.0.0.0/8" || len(out.Resolvers) != 1 {
		t.Errorf("%+v", out)
	}
	if !out.ReportOnly || out.Why == "" {
		t.Error("a snapshot with entries that made no sense may only report")
	}
	clean := &Snapshot{Owner: &Owner{PID: 3}, Routes: []SnapRoute{{Dest: "10.0.0.0/8", Iface: "Беспроводная сеть"}}}
	if err := saveSnapshotIn(dir, clean); err != nil {
		t.Fatal(err)
	}
	if out, _ := loadSnapshotIn(dir); out == nil || out.ReportOnly || len(out.Routes) != 1 {
		t.Errorf("a good snapshot is kept whole: %+v", out)
	}
}

func TestPlanNotesBelongToTheirSnapshot(t *testing.T) {
	dir := t.TempDir()
	if n, err := loadPlanNotesIn(dir, "t1"); n != nil || err != nil {
		t.Fatalf("%v %v", n, err)
	}
	if err := savePlanNotesIn(dir, &PlanNotes{Taken: "t1", Planned: []string{"10.0.0.0/8|a||0", "bad\x00"}, Kept: []string{"1.1.1.1/32|a||0"}}); err != nil {
		t.Fatal(err)
	}
	n, err := loadPlanNotesIn(dir, "t1")
	if err != nil || n == nil || len(n.Planned) != 1 || len(n.Kept) != 1 {
		t.Fatalf("%+v %v", n, err)
	}
	if n, _ := loadPlanNotesIn(dir, "t2"); n != nil {
		t.Error("the notes of another snapshot must not be used")
	}
	if err := removeSnapshotIn(dir); err != nil {
		t.Fatal(err)
	}
	if n, _ := loadPlanNotesIn(dir, "t1"); n != nil {
		t.Error("removing the snapshot removes its notes")
	}
}
