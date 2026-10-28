package router

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// nlmsg builds a received message the way the kernel sends it.
func nlmsg(typ, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 16, 16+len(payload)+3)
	binary.NativeEndian.PutUint32(b, uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	b = append(b, payload...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func errPayload(errno int32) []byte {
	b := make([]byte, 4+16) // the error and the header of the request
	binary.NativeEndian.PutUint32(b, uint32(errno))
	return b
}

func donePayload(errno int32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, uint32(errno))
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func errnoOf(t *testing.T, err error) int {
	t.Helper()
	var ne *nlError
	if !errors.As(err, &ne) {
		t.Fatalf("not a kernel error: %v", err)
	}
	return ne.errno
}

func TestNLReplyAck(t *testing.T) {
	needLE(t)
	var r nlReply
	done, err := r.feed(nlmsg(nlmsgError, 0, 7, errPayload(0)), 7)
	if !done || err != nil || len(r.payloads) != 0 {
		t.Errorf("ack: done=%v err=%v", done, err)
	}
}

func TestNLReplyKernelErrors(t *testing.T) {
	needLE(t)
	for name, errno := range map[string]int{"EEXIST": 17, "ESRCH": 3, "ENOENT": 2, "ENODEV": 19} {
		var r nlReply
		done, err := r.feed(nlmsg(nlmsgError, 0, 7, errPayload(int32(-errno))), 7)
		if !done || err == nil || errnoOf(t, err) != errno {
			t.Errorf("%s: done=%v err=%v", name, done, err)
		}
	}
	// a truncated error message is an error of its own, not a success
	var r nlReply
	if done, err := r.feed(nlmsg(nlmsgError, 0, 7, []byte{1, 2}), 7); !done || err == nil {
		t.Errorf("truncated: done=%v err=%v", done, err)
	}
}

func TestNLReplyMultipartDump(t *testing.T) {
	needLE(t)
	var r nlReply
	// the first read has two messages, the second one more and the end
	done, err := r.feed(cat(nlmsg(24, 2, 9, []byte{1, 1, 1, 1}), nlmsg(24, 2, 9, []byte{2, 2, 2, 2})), 9)
	if done || err != nil {
		t.Fatalf("not over yet: done=%v err=%v", done, err)
	}
	done, err = r.feed(cat(nlmsg(24, 2, 9, []byte{3, 3, 3, 3}), nlmsg(nlmsgDone, 2, 9, donePayload(0))), 9)
	if !done || err != nil || len(r.payloads) != 3 || r.payloads[2][0] != 3 {
		t.Errorf("done=%v err=%v payloads=%v", done, err, r.payloads)
	}
	// a DONE without the code (older kernels)
	var r2 nlReply
	if done, err := r2.feed(nlmsg(nlmsgDone, 2, 9, nil), 9); !done || err != nil {
		t.Errorf("done without code: %v %v", done, err)
	}
}

func TestNLReplyDoneWithErrno(t *testing.T) {
	needLE(t)
	var r nlReply
	done, err := r.feed(cat(nlmsg(24, 2, 9, []byte{1, 1, 1, 1}), nlmsg(nlmsgDone, 2, 9, donePayload(-1))), 9) // EPERM
	if !done || err == nil || errnoOf(t, err) != 1 {
		t.Errorf("a failed dump must fail: done=%v err=%v", done, err)
	}
}

func TestNLReplyDumpInterrupted(t *testing.T) {
	needLE(t)
	var r nlReply
	done, err := r.feed(cat(nlmsg(24, 2|nlmFDumpIntr, 9, []byte{1, 1, 1, 1}), nlmsg(nlmsgDone, 2, 9, donePayload(0))), 9)
	if !done || !errors.Is(err, errDumpIntr) {
		t.Errorf("done=%v err=%v", done, err)
	}
	// the flag on the DONE message alone is enough
	var r2 nlReply
	if _, err := r2.feed(nlmsg(nlmsgDone, 2|nlmFDumpIntr, 9, donePayload(0)), 9); !errors.Is(err, errDumpIntr) {
		t.Errorf("flag on DONE: %v", err)
	}
	// and the flag in an earlier read is remembered
	var r3 nlReply
	r3.feed(nlmsg(24, nlmFDumpIntr, 9, []byte{1, 1, 1, 1}), 9)
	if _, err := r3.feed(nlmsg(nlmsgDone, 2, 9, donePayload(0)), 9); !errors.Is(err, errDumpIntr) {
		t.Errorf("flag in an earlier read: %v", err)
	}
}

func TestNLReplyIgnoresOtherSequences(t *testing.T) {
	needLE(t)
	var r nlReply
	done, err := r.feed(cat(nlmsg(nlmsgError, 0, 3, errPayload(-17)), nlmsg(24, 2, 99, []byte{9, 9, 9, 9}), nlmsg(nlmsgDone, 2, 99, donePayload(-1))), 8)
	if done || err != nil || len(r.payloads) != 0 {
		t.Errorf("messages of other requests were taken: done=%v err=%v %v", done, err, r.payloads)
	}
	if done, err = r.feed(nlmsg(nlmsgError, 0, 8, errPayload(0)), 8); !done || err != nil {
		t.Errorf("done=%v err=%v", done, err)
	}
}

func TestNLReplyBrokenBuffer(t *testing.T) {
	needLE(t)
	var r nlReply
	good := nlmsg(24, 2, 9, []byte{1, 1, 1, 1})
	bad := append(append([]byte(nil), good...), 200, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0) // length past the end
	done, err := r.feed(bad, 9)
	if !done || err == nil {
		t.Errorf("done=%v err=%v", done, err)
	}
}

// nlExchange: sending, reading in several parts, errors of the socket.
func TestNLExchange(t *testing.T) {
	needLE(t)
	reads := [][]byte{
		nlmsg(24, 2, 5, []byte{1, 1, 1, 1}),
		cat(nlmsg(24, 2, 4, []byte{7, 7, 7, 7}), nlmsg(24, 2, 5, []byte{2, 2, 2, 2})), // one is another request's
		nlmsg(nlmsgDone, 2, 5, donePayload(0)),
	}
	i := 0
	var sent bool
	out, err := nlExchange(func() error { sent = true; return nil }, func(buf []byte) (int, error) {
		n := copy(buf, reads[i])
		i++
		return n, nil
	}, 5)
	if err != nil || !sent || len(out) != 2 || out[0][0] != 1 || out[1][0] != 2 {
		t.Errorf("%v %v %v", out, err, sent)
	}
	boom := errors.New("boom")
	if _, err := nlExchange(func() error { return boom }, nil, 5); !errors.Is(err, boom) {
		t.Errorf("send: %v", err)
	}
	if _, err := nlExchange(func() error { return nil }, func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }, 5); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("receive: %v", err)
	}
	// the kernel's answer to a request is an *nlError
	_, err = nlExchange(func() error { return nil }, func(buf []byte) (int, error) {
		return copy(buf, nlmsg(nlmsgError, 0, 5, errPayload(-17))), nil
	}, 5)
	if errnoOf(t, err) != 17 {
		t.Errorf("%v", err)
	}
}

func TestNLDumpRetriesAnInterruptedDump(t *testing.T) {
	calls := 0
	out, err := nlDump(func() ([][]byte, error) {
		calls++
		if calls < 3 {
			return nil, errDumpIntr
		}
		return [][]byte{{1}}, nil
	})
	if err != nil || calls != 3 || len(out) != 1 {
		t.Errorf("calls=%d out=%v err=%v", calls, out, err)
	}
	calls = 0
	if _, err = nlDump(func() ([][]byte, error) { calls++; return nil, errDumpIntr }); err == nil || calls != dumpTries {
		t.Errorf("a table that keeps changing is an error after %d tries: calls=%d err=%v", dumpTries, calls, err)
	}
	boom := errors.New("boom")
	calls = 0
	if _, err = nlDump(func() ([][]byte, error) { calls++; return nil, boom }); !errors.Is(err, boom) || calls != 1 {
		t.Errorf("other errors are not retried: calls=%d err=%v", calls, err)
	}
}
