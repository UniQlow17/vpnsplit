package router

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// The byte fixtures below are little-endian (host order on every OS this
// program runs on that has netlink: x86-64, arm64).
func needLE(t *testing.T) {
	t.Helper()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("fixtures are little-endian")
	}
}

func TestBuildAddRouteBytes(t *testing.T) {
	needLE(t)
	got := buildAddRoute(7, routeSpec{
		dest: netip.MustParsePrefix("10.1.2.0/24"), ifIndex: 9, gw: netip.MustParseAddr("192.168.1.1"), metric: 1, proto: routeProto,
	})
	want := []byte{
		// nlmsghdr: len 68, RTM_NEWROUTE, REQUEST|ACK|EXCL|CREATE (0x605), seq 7, pid 0
		0x44, 0, 0, 0, 0x18, 0, 0x05, 0x06, 7, 0, 0, 0, 0, 0, 0, 0,
		// rtmsg: AF_INET, dst_len 24, src_len 0, tos 0, table 254, protocol 247, scope universe, type unicast, flags 0
		2, 24, 0, 0, 254, 0xF7, 0, 1, 0, 0, 0, 0,
		8, 0, 1, 0, 10, 1, 2, 0, // RTA_DST
		8, 0, 4, 0, 9, 0, 0, 0, // RTA_OIF
		8, 0, 5, 0, 192, 168, 1, 1, // RTA_GATEWAY
		8, 0, 6, 0, 1, 0, 0, 0, // RTA_PRIORITY
		8, 0, 15, 0, 254, 0, 0, 0, // RTA_TABLE
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got  %x\nwant %x", got, want)
	}
}

func TestBuildAddRouteOnLinkHasLinkScopeAndNoGateway(t *testing.T) {
	needLE(t)
	got := buildAddRoute(1, routeSpec{dest: netip.MustParsePrefix("0.0.0.0/1"), ifIndex: 6, metric: 1, proto: routeProto})
	if got[16+6] != scopeLink {
		t.Errorf("scope %d", got[16+6])
	}
	if a := parseAttrs(got[28:]); a[rtaGateway] != nil || len(a[rtaDst]) != 4 {
		t.Errorf("attributes: %v", a)
	}
}

func TestBuildDelRouteMatchesOnProtocolOnlyWhenTagged(t *testing.T) {
	needLE(t)
	tagged := buildDelRoute(2, routeSpec{dest: netip.MustParsePrefix("10.1.2.0/24"), ifIndex: 9, metric: 1, proto: routeProto})
	legacy := buildDelRoute(2, routeSpec{dest: netip.MustParsePrefix("10.1.2.0/24"), ifIndex: 9, metric: 1})
	for _, c := range []struct {
		name  string
		b     []byte
		proto byte
	}{{"tagged", tagged, 0xF7}, {"legacy", legacy, 0}} {
		if nlEnd.Uint16(c.b[4:]) != rtmDelRoute || c.b[16+5] != c.proto || c.b[16+6] != scopeNowhere || c.b[16+1] != 24 {
			t.Errorf("%s: header %x", c.name, c.b[:28])
		}
		if nlEnd.Uint16(c.b[6:])&nlmFCreate != 0 {
			t.Errorf("%s: a delete must not carry CREATE", c.name)
		}
		if a := parseAttrs(c.b[28:]); nlEnd.Uint32(a[rtaPriority]) != 1 || nlEnd.Uint32(a[rtaOif]) != 9 {
			t.Errorf("%s: the metric and the device pick our route: %v", c.name, a)
		}
	}
}

func TestBuildRuleBytes(t *testing.T) {
	needLE(t)
	got := buildRule(rtmNewRule, 3, 247, 5000)
	want := []byte{
		0x34, 0, 0, 0, 0x20, 0, 0x05, 0x06, 3, 0, 0, 0, 0, 0, 0, 0, // len 52, RTM_NEWRULE, REQUEST|ACK|EXCL|CREATE
		2, 0, 0, 0, 247, 0, 0, 1, 0, 0, 0, 0, // fib_rule_hdr: no dst, no src, table 247, action FR_ACT_TO_TBL
		8, 0, 6, 0, 0x88, 0x13, 0, 0, // FRA_PRIORITY 5000
		8, 0, 15, 0, 247, 0, 0, 0, // FRA_TABLE 247
		5, 0, 21, 0, 0xF7, 0, 0, 0, // FRA_PROTOCOL 247, padded
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got  %x\nwant %x", got, want)
	}
	a := parseAttrs(got[28:])
	for _, sel := range []uint16{fraDst, fraSrc, fraFwmark, fraFwmask, fraIifname, fraOifname, fraUIDRange} {
		if _, ok := a[sel]; ok {
			t.Errorf("the rule has a selector (attribute %d): it must match every packet", sel)
		}
	}
	del := buildRule(rtmDelRule, 4, 247, 5000)
	if nlEnd.Uint16(del[6:])&(nlmFCreate|nlmFExcl) != 0 {
		t.Error("a rule delete must not carry CREATE|EXCL")
	}
}

func TestBuildAddRouteInOurTableAndReplace(t *testing.T) {
	needLE(t)
	s := routeSpec{dest: netip.MustParsePrefix("10.1.2.0/24"), ifIndex: 9, metric: 1, proto: routeProto, table: 247}
	add := buildAddRoute(1, s)
	if add[16+4] != 247 || nlEnd.Uint32(parseAttrs(add[28:])[rtaTable]) != 247 {
		t.Errorf("table: header %d, attribute %v", add[16+4], parseAttrs(add[28:])[rtaTable])
	}
	if f := nlEnd.Uint16(add[6:]); f&nlmFExcl == 0 || f&nlmFReplace != 0 {
		t.Errorf("an add is EXCL and not REPLACE: %x", f)
	}
	s.replace = true
	rep := buildAddRoute(1, s)
	if f := nlEnd.Uint16(rep[6:]); f&nlmFReplace == 0 || f&nlmFExcl != 0 {
		t.Errorf("a replace is REPLACE and not EXCL: %x", f)
	}
	del := buildDelRoute(2, s)
	if del[16+4] != 247 || nlEnd.Uint32(parseAttrs(del[28:])[rtaTable]) != 247 {
		t.Error("a delete names our table")
	}
	main := buildAddRoute(3, routeSpec{dest: netip.MustParsePrefix("10.1.2.0/24"), ifIndex: 9, metric: 1, proto: routeProto})
	if main[16+4] != 254 || nlEnd.Uint32(parseAttrs(main[28:])[rtaTable]) != 254 {
		t.Error("table 0 is main")
	}
}

// route builds a dump message the way the kernel does, independently of the builders.
func dumpRoute(dstLen, table, proto, typ byte, flags uint32, attrs ...[]byte) []byte {
	h := []byte{2, dstLen, 0, 0, table, proto, 0, typ, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(h[8:], flags)
	for _, a := range attrs {
		h = append(h, a...)
	}
	return h
}

func attr(typ uint16, data ...byte) []byte {
	b := make([]byte, (4+len(data)+3)&^3)
	binary.LittleEndian.PutUint16(b, uint16(4+len(data)))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func TestParseRoute(t *testing.T) {
	needLE(t)
	ours, ok := parseRoute(dumpRoute(24, 254, 0xF7, 1, 0,
		attr(1, 10, 1, 2, 0), attr(4, 9, 0, 0, 0), attr(5, 192, 168, 1, 1), attr(6, 1, 0, 0, 0), attr(15, 254, 0, 0, 0)))
	if !ok || ours.Dest != netip.MustParsePrefix("10.1.2.0/24") || ours.IfIndex != 9 || ours.Gateway != netip.MustParseAddr("192.168.1.1") ||
		ours.Metric != 1 || ours.Table != 0 || !ours.Ours {
		t.Errorf("%+v %v", ours, ok)
	}
	// the default route of a DHCP client: no RTA_DST, protocol dhcp, table from the header
	def, ok := parseRoute(dumpRoute(0, 254, 16, 1, 0, attr(4, 2, 0, 0, 0), attr(5, 192, 168, 1, 1), attr(6, 100, 0, 0, 0)))
	if !ok || def.Dest != netip.MustParsePrefix("0.0.0.0/0") || def.Ours || def.Metric != 100 || def.Table != 0 {
		t.Errorf("%+v %v", def, ok)
	}
	// a route of the client's own table (the number is in RTA_TABLE, the header says "unspec"/252)
	other, ok := parseRoute(dumpRoute(0, 252, 3, 1, 0, attr(4, 6, 0, 0, 0), attr(15, 0xE6, 0x07, 0, 0)))
	if !ok || other.Table != 2022 || other.Gateway.IsValid() {
		t.Errorf("%+v %v", other, ok)
	}
	for name, msg := range map[string][]byte{
		"cloned (cache) entry": dumpRoute(32, 254, 0, 1, rtmFCloned, attr(1, 1, 1, 1, 1), attr(4, 2, 0, 0, 0)),
		"local table route":    dumpRoute(32, 255, 2, 2, 0, attr(1, 1, 1, 1, 1), attr(4, 1, 0, 0, 0)), // RTN_LOCAL
		"multipath":            dumpRoute(24, 254, 3, 1, 0, attr(1, 1, 1, 1, 0)),
		"truncated":            {2, 24, 0},
		"IPv6":                 append([]byte{10, 64, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0}, attr(4, 2, 0, 0, 0)...),
	} {
		if r, ok := parseRoute(msg); ok {
			t.Errorf("%s: parsed as %+v", name, r)
		}
	}
}

func dumpRule(dstLen, table, action byte, flags uint32, attrs ...[]byte) []byte {
	h := []byte{2, dstLen, 0, 0, table, 0, 0, action, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(h[8:], flags)
	for _, a := range attrs {
		h = append(h, a...)
	}
	return h
}

func TestParseRules(t *testing.T) {
	needLE(t)
	// sing-box: not fwmark 2022 lookup 2022 pref 9000
	sb, ok := parseRule(dumpRule(0, 252, 1, fibRuleInv, attr(6, 0x28, 0x23, 0, 0), attr(10, 0xE6, 7, 0, 0), attr(15, 0xE6, 7, 0, 0)))
	if !ok || sb.Pref != 9000 || sb.Table != 2022 || !sb.ToTable || !sb.Fwmark || !sb.Inv || sb.OtherSel || sb.Suppress != -1 || sb.Ours || !ruleDiverts(sb) {
		t.Errorf("%+v %v", sb, ok)
	}
	// wg-quick: lookup main suppress_prefixlength 0 pref 32764
	wg, ok := parseRule(dumpRule(0, 254, 1, 0, attr(6, 0xFC, 0x7F, 0, 0), attr(14, 0, 0, 0, 0)))
	if !ok || wg.Pref != 32764 || wg.Table != RuleTableMain || wg.Suppress != 0 || wg.hasSel() || ruleDiverts(wg) {
		t.Errorf("%+v %v", wg, ok)
	}
	// suppress_prefixlength absent is -1; the kernel's own rule 0
	local, ok := parseRule(dumpRule(0, 255, 1, 0, attr(6, 0, 0, 0, 0)))
	if !ok || local.Pref != 0 || local.Suppress != -1 || ruleDiverts(local) {
		t.Errorf("%+v %v", local, ok)
	}
	// ours: lookup 247 pref 5000 proto 247, no selector
	our, ok := parseRule(dumpRule(0, 247, 1, 0, attr(6, 0x88, 0x13, 0, 0), attr(15, 247, 0, 0, 0), attr(21, 0xF7)))
	k, shape := our.isOurShape()
	if !ok || !our.Ours || !shape || k != (ruleKey{247, 5000}) {
		t.Errorf("%+v %v %v", our, ok, k)
	}
	// the same without our tag is somebody else's
	other, _ := parseRule(dumpRule(0, 247, 1, 0, attr(6, 0x88, 0x13, 0, 0), attr(15, 247, 0, 0, 0)))
	if _, shape := other.isOurShape(); shape {
		t.Error("an untagged rule is not ours")
	}
	// a rule with a source is not the shape of ours
	src := dumpRule(24, 247, 1, 0, attr(1, 203, 0, 113, 0), attr(2, 10, 0, 0, 0), attr(6, 0x88, 0x13, 0, 0), attr(21, 0xF7))
	src[2] = 8
	if r, _ := parseRule(src); func() bool { _, s := r.isOurShape(); return s }() {
		t.Errorf("a rule with a source taken for ours: %+v", r)
	}
}

// Which rules send all traffic past the main table, by what the kernel reports.
func TestRuleSelectors(t *testing.T) {
	needLE(t)
	mark := attr(10, 0xE6, 7, 0, 0)
	cases := []struct {
		name     string
		msg      []byte
		diverts  bool
		fwmark   bool
		otherSel bool
	}{
		{"plain lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(15, 77, 0, 0, 0)), true, false, false},
		{"not fwmark X lookup 77", dumpRule(0, 77, 1, fibRuleInv, attr(6, 100, 0, 0, 0), mark, attr(15, 77, 0, 0, 0)), true, true, false},
		{"fwmark X lookup 77 (only the marked packets)", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), mark, attr(15, 77, 0, 0, 0)), false, true, false},
		{"uidrange lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(20, 1, 0, 0, 0, 2, 0, 0, 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"not uidrange lookup 77", dumpRule(0, 77, 1, fibRuleInv, attr(6, 100, 0, 0, 0), attr(20, 1, 0, 0, 0, 2, 0, 0, 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"iif lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(3, 'e', 't', 'h', '0', 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"oif lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(17, 'e', 't', 'h', '0', 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"ipproto tcp lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(22, 6), attr(15, 77, 0, 0, 0)), false, false, true},
		{"dport lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(24, 80, 0, 80, 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"sport lookup 77", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(23, 80, 0, 80, 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"l3mdev", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(19, 1), attr(15, 77, 0, 0, 0)), false, false, true},
		{"suppress_ifgroup", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(13, 5, 0, 0, 0), attr(15, 77, 0, 0, 0)), false, false, true},
		{"suppress_prefixlength 0", dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(14, 0, 0, 0, 0), attr(15, 77, 0, 0, 0)), false, false, false},
		{"not (no selector at all)", dumpRule(0, 77, 1, fibRuleInv, attr(6, 100, 0, 0, 0), attr(15, 77, 0, 0, 0)), false, false, false},
	}
	for _, c := range cases {
		r, ok := parseRule(c.msg)
		if !ok {
			t.Errorf("%s: not parsed", c.name)
			continue
		}
		if ruleDiverts(r) != c.diverts || r.Fwmark != c.fwmark || r.OtherSel != c.otherSel {
			t.Errorf("%s: %+v diverts=%v, want diverts=%v fwmark=%v other=%v", c.name, r, ruleDiverts(r), c.diverts, c.fwmark, c.otherSel)
		}
	}
	// tos is a selector too (byte 3 of the header)
	tos := dumpRule(0, 77, 1, 0, attr(6, 100, 0, 0, 0), attr(15, 77, 0, 0, 0))
	tos[3] = 0x10
	if r, _ := parseRule(tos); ruleDiverts(r) || !r.OtherSel {
		t.Errorf("tos: %+v", r)
	}
	// a rule for one source or destination does not divert everything
	src := dumpRule(24, 77, 1, 0, attr(1, 203, 0, 113, 0), attr(6, 100, 0, 0, 0), attr(15, 77, 0, 0, 0))
	if r, _ := parseRule(src); ruleDiverts(r) {
		t.Errorf("dst: %+v", r)
	}
}

func TestSplitAndAck(t *testing.T) {
	needLE(t)
	mk := func(typ uint16, seq uint32, payload []byte) []byte {
		b := make([]byte, 16, 16+len(payload))
		binary.LittleEndian.PutUint32(b, uint32(16+len(payload)))
		binary.LittleEndian.PutUint16(b[4:], typ)
		binary.LittleEndian.PutUint32(b[8:], seq)
		b = append(b, payload...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	buf := append(mk(24, 5, []byte{1, 2, 3, 4, 5}), mk(nlmsgDone, 5, []byte{0, 0, 0, 0})...)
	msgs, err := splitNL(buf)
	if err != nil || len(msgs) != 2 || msgs[0].typ != 24 || len(msgs[0].payload) != 5 || msgs[1].typ != nlmsgDone {
		t.Fatalf("%+v %v", msgs, err)
	}
	// NLMSG_ERROR with -EEXIST (-17) and with 0 (an ack)
	e := make([]byte, 4)
	binary.LittleEndian.PutUint32(e, uint32(0xFFFFFFEF))
	m, _ := splitNL(mk(nlmsgError, 1, e))
	if n, err := nlErrno(m[0]); err != nil || n != 17 {
		t.Errorf("errno %d %v", n, err)
	}
	m, _ = splitNL(mk(nlmsgError, 1, make([]byte, 4)))
	if n, _ := nlErrno(m[0]); n != 0 {
		t.Errorf("ack is %d", n)
	}
	if _, err := splitNL([]byte{200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("a length past the buffer must be an error")
	}
}

func TestParseAttrsStopsOnGarbage(t *testing.T) {
	needLE(t)
	b := append(attr(1, 1, 2, 3, 4), 0xFF, 0xFF, 1, 0, 9, 9, 9, 9) // an attribute longer than the rest
	if a := parseAttrs(b); len(a) != 1 {
		t.Errorf("%v", a)
	}
}

func TestParseRouteInOurTable(t *testing.T) {
	needLE(t)
	r, ok := parseRoute(dumpRoute(24, 247, 0xF7, 1, 0, attr(1, 10, 1, 2, 0), attr(4, 9, 0, 0, 0), attr(6, 1, 0, 0, 0), attr(15, 247, 0, 0, 0)))
	if !ok || r.Table != 247 || !r.Ours {
		t.Errorf("%+v", r)
	}
	if !holdsOurs(r.Table) || holdsOurs(2022) || !holdsOurs(0) {
		t.Error("holdsOurs")
	}
}

func TestRouteProtoIsFree(t *testing.T) {
	// the ids named in iproute2's rt_protos and linux/rtnetlink.h
	for _, used := range []int{0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 42, 99, 84, 186, 187, 188, 189, 192} {
		if routeProto == used {
			t.Errorf("protocol %d is taken", used)
		}
	}
}
