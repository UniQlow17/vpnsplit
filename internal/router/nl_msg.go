package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// rtnetlink messages (Linux), built and read by hand. The constants are the
// kernel's stable ABI (linux/netlink.h, rtnetlink.h, fib_rules.h). This file
// has no build constraint so that the encoding is tested on every OS; the
// socket itself is in nl_linux.go.

const (
	nlmsgError = 2
	nlmsgDone  = 3

	nlmFRequest  = 0x1
	nlmFAck      = 0x4
	nlmFDumpIntr = 0x10 // NLM_F_DUMP_INTR: the table changed during the dump, the result is not consistent
	nlmFReplace  = 0x100
	nlmFRoot     = 0x100
	nlmFMatch    = 0x200
	nlmFDump     = nlmFRoot | nlmFMatch
	nlmFExcl     = 0x200
	nlmFCreate   = 0x400

	rtmNewRoute = 24
	rtmDelRoute = 25
	rtmGetRoute = 26
	rtmNewRule  = 32
	rtmDelRule  = 33
	rtmGetRule  = 34

	rtaDst      = 1
	rtaOif      = 4
	rtaGateway  = 5
	rtaPriority = 6
	rtaTable    = 15

	fraDst            = 1
	fraSrc            = 2
	fraIifname        = 3
	fraGoto           = 4
	fraPriority       = 6
	fraFwmark         = 10
	fraTunID          = 12
	fraSuppressIfgrp  = 13
	fraSuppressPrefix = 14
	fraTable          = 15
	fraFwmask         = 16
	fraOifname        = 17
	fraL3mdev         = 19
	fraUIDRange       = 20
	fraProtocol       = 21
	fraIPProto        = 22
	fraSport          = 23
	fraDport          = 24

	frActToTbl  = 1
	fibRuleInv  = 0x2 // FIB_RULE_INVERT
	rtmFCloned  = 0x200
	rtnUnicast  = 1
	rtTableMain = 254
	afInet      = 2

	scopeUniverse = 0
	scopeLink     = 253
	scopeNowhere  = 255

	// routeProto is rtm_protocol (and the protocol of a rule) of everything
	// vpnsplit creates. iproute2 names 0-16, 18, 42, 186-189 and 192 in
	// rt_protos; the kernel itself uses 1-4 and a few daemons' ids sit in
	// 8-16. 247 (0xF7) is free in all of them. It is also the number of our
	// routing table (config.OwnTable): the two namespaces are separate.
	routeProto = 0xF7
)

var nlEnd = binary.NativeEndian

func align4(n int) int { return (n + 3) &^ 3 }

// nlAttr is one attribute: length, type, data, padding to 4 bytes.
func nlAttr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(4+len(data)))
	nlEnd.PutUint16(b[0:], uint16(4+len(data)))
	nlEnd.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func attrU32(typ uint16, v uint32) []byte {
	var d [4]byte
	nlEnd.PutUint32(d[:], v)
	return nlAttr(typ, d[:])
}

func attrAddr(typ uint16, a netip.Addr) []byte {
	b := a.As4()
	return nlAttr(typ, b[:])
}

// nlMessage is a netlink header followed by hdr (rtmsg or fib_rule_hdr) and attributes.
func nlMessage(typ, flags uint16, seq uint32, hdr []byte, attrs ...[]byte) []byte {
	n := 16 + len(hdr)
	for _, a := range attrs {
		n += len(a)
	}
	b := make([]byte, 16, n)
	nlEnd.PutUint32(b[0:], uint32(n))
	nlEnd.PutUint16(b[4:], typ)
	nlEnd.PutUint16(b[6:], flags)
	nlEnd.PutUint32(b[8:], seq)
	b = append(b, hdr...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// routeSpec is what a route message carries.
type routeSpec struct {
	dest    netip.Prefix
	ifIndex int
	gw      netip.Addr // invalid: on-link
	metric  int
	proto   uint8 // 0: any (a legacy route without our tag)
	table   int   // 0: main
	replace bool  // NLM_F_REPLACE instead of NLM_F_EXCL: take the place of the route with the same key
}

func (s routeSpec) tableID() uint32 {
	if s.table == 0 {
		return rtTableMain
	}
	return uint32(s.table)
}

// tableByte is the rtm_table field: tables above 255 are in RTA_TABLE only.
func tableByte(t uint32) byte {
	if t > 255 {
		return 252 // RT_TABLE_COMPAT
	}
	return byte(t)
}

func routeAttrs(s routeSpec) [][]byte {
	attrs := [][]byte{attrAddr(rtaDst, s.dest.Addr()), attrU32(rtaOif, uint32(s.ifIndex))}
	if s.gw.IsValid() {
		attrs = append(attrs, attrAddr(rtaGateway, s.gw))
	}
	return append(attrs, attrU32(rtaPriority, uint32(s.metric)), attrU32(rtaTable, s.tableID()))
}

// buildAddRoute is "ip route add <dest> [via gw] dev X metric M proto 247
// [table T]". NLM_F_EXCL: a route that is there already is the client's and
// must stay. With s.replace it is "ip route replace": the caller has checked
// that the route in the way is ours (a move of our own route to another device).
func buildAddRoute(seq uint32, s routeSpec) []byte {
	hdr := make([]byte, 12)
	hdr[0] = afInet
	hdr[1] = byte(s.dest.Bits())
	hdr[4] = tableByte(s.tableID())
	hdr[5] = s.proto
	hdr[6] = scopeLink
	if s.gw.IsValid() {
		hdr[6] = scopeUniverse
	}
	hdr[7] = rtnUnicast
	flags := uint16(nlmFRequest | nlmFAck | nlmFCreate | nlmFExcl)
	if s.replace {
		flags = nlmFRequest | nlmFAck | nlmFCreate | nlmFReplace
	}
	return nlMessage(rtmNewRoute, flags, seq, hdr, routeAttrs(s)...)
}

// buildDelRoute removes the route that matches destination, device, next hop,
// metric, table and protocol (0: any, for routes of older versions). The
// kernel matches only on what is given, so a client's route to the same place
// (another metric or protocol) stays.
func buildDelRoute(seq uint32, s routeSpec) []byte {
	hdr := make([]byte, 12)
	hdr[0] = afInet
	hdr[1] = byte(s.dest.Bits())
	hdr[4] = tableByte(s.tableID())
	hdr[5] = s.proto
	hdr[6] = scopeNowhere
	return nlMessage(rtmDelRoute, nlmFRequest|nlmFAck, seq, hdr, routeAttrs(s)...)
}

// buildDumpRoutes asks for all IPv4 routes of all tables.
func buildDumpRoutes(seq uint32) []byte {
	hdr := make([]byte, 12)
	hdr[0] = afInet
	return nlMessage(rtmGetRoute, nlmFRequest|nlmFDump, seq, hdr)
}

func buildDumpRules(seq uint32) []byte {
	hdr := make([]byte, 12)
	hdr[0] = afInet
	return nlMessage(rtmGetRule, nlmFRequest|nlmFDump, seq, hdr)
}

// buildRule is "ip rule add|del pref P lookup T proto 247": no selector, so
// it matches every packet; a packet that finds no route in T goes on to the
// next rule.
func buildRule(typ uint16, seq uint32, table, pref int) []byte {
	hdr := make([]byte, 12)
	hdr[0] = afInet
	hdr[4] = tableByte(uint32(table))
	hdr[7] = frActToTbl
	flags := uint16(nlmFRequest | nlmFAck)
	if typ == rtmNewRule {
		flags |= nlmFCreate | nlmFExcl
	}
	return nlMessage(typ, flags, seq, hdr,
		attrU32(fraPriority, uint32(pref)),
		attrU32(fraTable, uint32(table)),
		nlAttr(fraProtocol, []byte{routeProto}))
}

// nlMsg is one message of a received buffer.
type nlMsg struct {
	typ, flags uint16
	seq        uint32
	payload    []byte
}

func splitNL(b []byte) ([]nlMsg, error) {
	var out []nlMsg
	for len(b) >= 16 {
		n := int(nlEnd.Uint32(b[0:]))
		if n < 16 || n > len(b) {
			return out, fmt.Errorf("netlink: bad message length %d of %d", n, len(b))
		}
		out = append(out, nlMsg{typ: nlEnd.Uint16(b[4:]), flags: nlEnd.Uint16(b[6:]), seq: nlEnd.Uint32(b[8:]), payload: b[16:n]})
		b = b[min(align4(n), len(b)):]
	}
	return out, nil
}

// nlErrno is the errno an NLMSG_ERROR message carries (0: an ack).
func nlErrno(m nlMsg) (int, error) {
	if m.typ != nlmsgError || len(m.payload) < 4 {
		return 0, errors.New("netlink: not an error message")
	}
	return -int(int32(nlEnd.Uint32(m.payload))), nil
}

// nlError is an error code of the kernel. nl_linux.go turns it into unix.Errno.
type nlError struct{ errno int }

func (e *nlError) Error() string { return fmt.Sprintf("netlink: kernel error %d", e.errno) }

// errDumpIntr: the kernel marked a dump NLM_F_DUMP_INTR, the table changed while
// it was read. The result may miss or repeat entries: ask again.
var errDumpIntr = errors.New("netlink: the dump was interrupted by a change of the table")

// nlReply collects the answer to one request.
type nlReply struct {
	payloads [][]byte
	intr     bool
}

// feed processes one received buffer for the request with sequence number seq.
// Messages of other requests are ignored. done is true when the answer is
// complete: NLMSG_DONE (a dump), or NLMSG_ERROR (the ack of a request or its
// failure). A non-zero code of the kernel is an *nlError, in NLMSG_DONE too
// (the kernel reports a failed dump there). A dump that carries
// NLM_F_DUMP_INTR ends with errDumpIntr.
func (r *nlReply) feed(buf []byte, seq uint32) (done bool, err error) {
	msgs, perr := splitNL(buf)
	for _, m := range msgs {
		if m.seq != seq {
			continue
		}
		if m.flags&nlmFDumpIntr != 0 {
			r.intr = true
		}
		switch m.typ {
		case nlmsgDone:
			if len(m.payload) >= 4 {
				if code := -int(int32(nlEnd.Uint32(m.payload))); code != 0 {
					return true, &nlError{code}
				}
			}
			if r.intr {
				return true, errDumpIntr
			}
			return true, nil
		case nlmsgError:
			code, e := nlErrno(m)
			if e != nil {
				return true, e
			}
			if code != 0 {
				return true, &nlError{code}
			}
			return true, nil // the ack of a request
		default:
			r.payloads = append(r.payloads, append([]byte(nil), m.payload...))
		}
	}
	if perr != nil {
		return true, perr
	}
	return false, nil
}

// nlExchange sends a request and reads until the answer to seq is complete.
// recv fills buf and returns the number of bytes (EINTR is its business).
func nlExchange(send func() error, recv func(buf []byte) (int, error), seq uint32) ([][]byte, error) {
	if err := send(); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}
	var r nlReply
	buf := make([]byte, 1<<16)
	for {
		n, err := recv(buf)
		if err != nil {
			return nil, fmt.Errorf("netlink receive: %w", err)
		}
		done, err := r.feed(buf[:n], seq)
		if err != nil {
			return nil, err
		}
		if done {
			return r.payloads, nil
		}
	}
}

// dumpTries is how often a dump that the kernel marked as interrupted by a
// change of the table is asked for again.
const dumpTries = 3

// nlDump runs a dump (try opens a socket and does it) again while the kernel
// says it was interrupted; after dumpTries the table is reported as unreadable.
func nlDump(try func() ([][]byte, error)) ([][]byte, error) {
	var err error
	for range dumpTries {
		var out [][]byte
		if out, err = try(); !errors.Is(err, errDumpIntr) {
			return out, err
		}
	}
	return nil, fmt.Errorf("the table kept changing during %d reads: %w", dumpTries, err)
}

// parseAttrs returns the first attribute of each type.
func parseAttrs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		n := int(nlEnd.Uint16(b[0:]))
		if n < 4 || n > len(b) {
			break
		}
		t := nlEnd.Uint16(b[2:]) &^ 0xC000 // NLA_F_NESTED, NLA_F_NET_BYTEORDER
		if _, ok := out[t]; !ok {
			out[t] = b[4:n]
		}
		b = b[min(align4(n), len(b)):]
	}
	return out
}

func addr4(b []byte) netip.Addr {
	if len(b) < 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(b[:4]))
}

func u32(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return nlEnd.Uint32(b), true
}

// parseRoute reads an RTM_NEWROUTE message of a dump. Routes that are not
// IPv4 unicast, cache entries and multipath routes (no single device) are skipped.
func parseRoute(payload []byte) (OSRoute, bool) {
	if len(payload) < 12 || payload[0] != afInet || payload[7] != rtnUnicast {
		return OSRoute{}, false
	}
	if nlEnd.Uint32(payload[8:])&rtmFCloned != 0 {
		return OSRoute{}, false
	}
	a := parseAttrs(payload[12:])
	oif, ok := u32(a[rtaOif])
	if !ok {
		return OSRoute{}, false
	}
	dst := addr4(a[rtaDst])
	if !dst.IsValid() {
		dst = netip.IPv4Unspecified()
	}
	p, err := dst.Prefix(int(payload[1]))
	if err != nil {
		return OSRoute{}, false
	}
	table := int(payload[4])
	if t, ok := u32(a[rtaTable]); ok {
		table = int(t)
	}
	if table == rtTableMain {
		table = 0
	}
	metric, _ := u32(a[rtaPriority])
	return OSRoute{
		Dest: p, IfIndex: int(oif), Gateway: addr4(a[rtaGateway]), Metric: int(metric),
		Table: table, Ours: payload[5] == routeProto, Proto: int(payload[5]),
	}, true
}

// parseRule reads an RTM_NEWRULE message of a dump.
func parseRule(payload []byte) (OSRule, bool) {
	if len(payload) < 12 || payload[0] != afInet {
		return OSRule{}, false
	}
	a := parseAttrs(payload[12:])
	r := OSRule{Suppress: -1, ToTable: payload[7] == frActToTbl, Table: int(payload[4])}
	if t, ok := u32(a[fraTable]); ok {
		r.Table = int(t)
	}
	if v, ok := u32(a[fraPriority]); ok {
		r.Pref = int(v)
	}
	if v, ok := u32(a[fraSuppressPrefix]); ok {
		r.Suppress = int(int32(v))
	}
	if d := addr4(a[fraDst]); d.IsValid() && payload[1] > 0 {
		r.Dest, _ = d.Prefix(int(payload[1]))
	}
	if s := addr4(a[fraSrc]); s.IsValid() && payload[2] > 0 {
		r.Src, _ = s.Prefix(int(payload[2]))
	}
	// The fwmark is the selector clients use to tell their own packets ("not
	// fwmark X lookup X"); every other selector narrows the rule to part of
	// the traffic.
	_, hasMark := a[fraFwmark]
	_, hasMask := a[fraFwmask]
	r.Fwmark = hasMark || hasMask
	for _, t := range []uint16{fraIifname, fraOifname, fraL3mdev, fraUIDRange, fraIPProto, fraSport, fraDport, fraTunID} {
		if _, ok := a[t]; ok {
			r.OtherSel = true
		}
	}
	if payload[3] != 0 { // tos
		r.OtherSel = true
	}
	if v, ok := u32(a[fraSuppressIfgrp]); ok && int32(v) != -1 { // the result is filtered by interface group
		r.OtherSel = true
	}
	r.Inv = nlEnd.Uint32(payload[8:])&fibRuleInv != 0
	if p := a[fraProtocol]; len(p) >= 1 {
		r.Ours = p[0] == routeProto
	}
	return r, true
}
