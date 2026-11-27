// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// This file is the per-session net.PacketConn shim that sits between kcp-go and
// the real UDP socket (§8.5). One shim per
// promoted session. Its WriteTo seals every outbound datagram under THAT
// session's own k_kcp_s2c and seq_full allocator — the per-session seal context
// that closes the retired-session-flush nonce-reuse hazard. Its ReadFrom blocks
// until the server's master loop feeds it a decrypted KCP datagram.
//
// It is a plain struct on purpose: it MUST NOT expose SyscallConn/ReadMsgUDP, or
// kcp-go's Linux batch read path bypasses ReadFrom and reads the raw socket,
// defeating the demux (design §4).

var errSeqExhausted = errors.New("shieldnet: s2c seq_full exhausted")

type sessionConn struct {
	real  net.PacketConn // the shared UDP socket, for WriteTo
	raddr net.Addr       // the client's address
	// kmu guards key against wipe: kcp-go's update goroutine can still call
	// WriteTo after Close returns, so wipe takes kmu and later seals fail.
	kmu     sync.Mutex
	key     []byte      // this session's outbound seal key (k_kcp_s2c server / k_kcp_c2s client)
	wiped   bool        // key zeroed; WriteTo refuses (guarded by kmu)
	seq     *sender     // this session's outbound seq_full allocator
	c2s     bool        // seal direction: false = s2c (server), true = c2s (client)
	inbound chan []byte // master loop pushes decrypted KCP datagrams here
	closed  chan struct{}
	once    sync.Once

	// Client only (c2s): transport 10.3's "unacknowledged data outstanding",
	// which kcp-go does not export. ackMu makes "record a PUSH sent, then open
	// the gate" (WriteTo) and "record una, then maybe close it" (ackSeen) one
	// critical section each, so a PUSH emitted between a compare and a clear is
	// not lost. They live on the shim, which is per session, so a re-admission
	// starts from nothing.
	ackMu  sync.Mutex
	maxSn  uint32 // highest PUSH sn sent, in serial arithmetic
	sentSn bool   // a PUSH has been sent
	una    uint32 // largest una received, in serial arithmetic
	gotUna bool   // a una has been received
	onPush func() // the client's markOutstanding; nil on the server
}

// newSessionConn builds the shim for one session. rcvWnd is the session's KCP
// receive window: inbound holds at least that many datagrams, so a segment the
// window admits is not dropped here (transport 13 item 5).
func newSessionConn(real net.PacketConn, raddr net.Addr, key []byte, c2s bool, rcvWnd int) *sessionConn {
	return &sessionConn{
		real:    real,
		raddr:   raddr,
		key:     key,
		seq:     newSender(),
		c2s:     c2s,
		inbound: make(chan []byte, max(64, rcvWnd)),
		closed:  make(chan struct{}),
	}
}

// deliver hands a decrypted KCP datagram to kcp-go's read loop. Non-blocking on a
// closed session; drops if the buffer, sized to the receive window, is full
// (KCP retransmits under a fresh outer sequence, §8.2).
func (c *sessionConn) deliver(kcpBytes []byte) {
	b := append([]byte(nil), kcpBytes...)
	clearFrg(b)
	select {
	case c.inbound <- b:
	case <-c.closed:
	default:
	}
}

func (c *sessionConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-c.inbound:
		return copy(p, b), c.raddr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo seals a KCP datagram from kcp-go and sends it on the shared socket.
// §8.4: a fresh s2c seq_full per emitted datagram, fail-closed on wrap.
//
// Socket errors are reported to kcp-go as success. kcp-go latches the first
// write error for the life of the session (UDPSession.notifyWriteError) and
// fails every later Write with it, while retransmission carries on underneath,
// so liveness never fires. A transient ENOBUFS, or an ICMP error surfaced on the
// client's connected socket (port unreachable → ECONNREFUSED, spoofed
// frag-needed → EMSGSIZE; §7.6 says ICMP MUST be ignored), would end the
// session's ability to send without ending the session. Treating the datagram
// as lost lets KCP retransmit it, as it would any other loss. Only
// seq exhaustion and a wiped key, which are permanent, are returned.
func (c *sessionConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	seq, ok := c.seq.alloc()
	if !ok {
		return 0, errSeqExhausted
	}
	c.kmu.Lock()
	if c.wiped {
		c.kmu.Unlock()
		return 0, net.ErrClosed
	}
	env, err := Seal(c.key, c.c2s, seq, p)
	c.kmu.Unlock()
	if err != nil {
		return 0, err
	}
	// Only after a successful seal: a retired session's PUSHes, still draining
	// through kcp-go after Close, fail on the wiped key and mark nothing.
	if c.onPush != nil {
		c.pushSent(p)
	}
	_, _ = c.real.WriteTo(env, c.raddr) // see above: a send error is a lost datagram
	return len(p), nil
}

// wipe zeroes the seal key; every later WriteTo fails with net.ErrClosed.
// Call it after kcp-go's Close, whose final flush still needs the key.
func (c *sessionConn) wipe() {
	c.kmu.Lock()
	zero(c.key)
	c.wiped = true
	c.kmu.Unlock()
}

// KCP segment layout (ikcp): conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4)
// len(4), then len payload octets.
const (
	kcpFrgOff = 5
	kcpSnOff  = 12
	kcpUnaOff = 16
	kcpLenOff = 20
)

// clearFrg zeroes the frg field of every segment in a decrypted KCP datagram.
// Sessions run in stream mode, where frg carries no meaning, but kcp-go keeps a
// peer's frg anyway and PeekSize then waits for frg+1 segments; with the
// lowered rcv_wnd they never all fit, so one segment with frg >= rcv_wnd stalls
// the receive stream for good. libshieldnet's ikcp fork ignores frg in stream
// mode for the same reason. A malformed tail is left for kcp-go to reject.
func clearFrg(b []byte) {
	for off := 0; off+KcpOverhead <= len(b); {
		b[off+kcpFrgOff] = 0
		n := binary.LittleEndian.Uint32(b[off+kcpLenOff:])
		if uint64(n) > uint64(len(b)-off-KcpOverhead) {
			return
		}
		off += KcpOverhead + int(n)
	}
}

// pushSent records the highest PUSH sn in an outbound datagram and opens the
// client's outstanding gate. kcp-go numbers data only when it leaves snd_queue,
// which cwnd and the peer's window can delay long after the application's
// write, so the PUSH going out must re-open the gate when it does.
func (c *sessionConn) pushSent(p []byte) {
	sn, ok := maxPushSn(p)
	if !ok {
		return
	}
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	if !c.sentSn || int32(sn-c.maxSn) > 0 {
		c.maxSn, c.sentSn = sn, true
	}
	// A retransmit of data the peer's una already covers is not outstanding:
	// kcp-go may resend it before it has processed the ACK we have seen, and if
	// the peer's ACK for the duplicate is lost, nothing would ever close the
	// gate again on an idle session.
	if c.gotUna && int32(sn-c.una) < 0 {
		return
	}
	c.onPush()
}

// ackSeen records the una of an accepted inbound datagram and calls clear when
// every PUSH sent so far has been acknowledged (una past the highest sn sent).
// With no PUSH sent yet there is nothing unacknowledged.
func (c *sessionConn) ackSeen(pt []byte, clear func()) {
	una, ok := maxUna(pt)
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	if ok && (!c.gotUna || int32(una-c.una) > 0) {
		c.una, c.gotUna = una, true
	}
	if !c.sentSn || (c.gotUna && int32(c.una-(c.maxSn+1)) >= 0) {
		clear()
	}
}

// maxPushSn returns the highest sn among the well-formed PUSH segments of a KCP
// datagram, in serial arithmetic, and whether there was one.
func maxPushSn(b []byte) (uint32, bool) {
	var max uint32
	found := false
	walkSegments(b, func(seg []byte) {
		if seg[4] != kcpCmdPush {
			return
		}
		sn := binary.LittleEndian.Uint32(seg[kcpSnOff:])
		if !found || int32(sn-max) > 0 {
			max, found = sn, true
		}
	})
	return max, found
}

// maxUna returns the largest una among the well-formed segments of a KCP
// datagram, in serial arithmetic, and whether there was one.
func maxUna(b []byte) (uint32, bool) {
	var max uint32
	found := false
	walkSegments(b, func(seg []byte) {
		una := binary.LittleEndian.Uint32(seg[kcpUnaOff:])
		if !found || int32(una-max) > 0 {
			max, found = una, true
		}
	})
	return max, found
}

// walkSegments calls f with each whole segment of a KCP datagram (header and
// payload). It stops at the first segment whose len runs past the datagram,
// as kcp-go's input does, so f never sees a truncated one.
func walkSegments(b []byte, f func(seg []byte)) {
	for off := 0; off+KcpOverhead <= len(b); {
		n := binary.LittleEndian.Uint32(b[off+kcpLenOff:])
		if uint64(n) > uint64(len(b)-off-KcpOverhead) {
			return
		}
		end := off + KcpOverhead + int(n)
		f(b[off:end])
		off = end
	}
}

func (c *sessionConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *sessionConn) LocalAddr() net.Addr                { return c.real.LocalAddr() }
func (c *sessionConn) SetDeadline(t time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(t time.Time) error { return nil }
