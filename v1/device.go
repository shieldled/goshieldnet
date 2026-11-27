// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/crypto/curve25519"
)

// This file is the device state machine. Steps 2–3:
// the stateless §6.1 INIT → RETRY response and the stateful §6.2 FINISH → ADMIT
// with the §6.3 tuple-keyed pending table. Promotion (§8.5), the §9.2 tick and
// §10 locks arrive in later steps. Until the lock step a Device is used from one
// goroutine, so the §6.2-step-7 re-check is structurally present but cannot yet
// observe a concurrent writer.

// CookieEpochMS is COOKIE_EPOCH_MS (§2): the cookie/epoch_tag rotation period.
const CookieEpochMS = 4000

// PendingTTLMS is PENDING_TTL_MS (§2): a pending record's lifetime.
const PendingTTLMS = 5000

// §2 client timing constants (milliseconds). Used by the §7 client.
const (
	InitRetryMS       = 1000 // INIT_RETRY_MS; 3 transmissions
	InitTransmissions = 3
	FinishRetryMS     = 500  // FINISH_RETRY_MS
	FinishPhaseMS     = 1500 // FINISH phase cap
	PushAckTimeoutMS  = 2000 // PUSH_ACK_TIMEOUT_MS
	SessionDeadMS     = 10000

	// SendBlockedMS bounds how long an application write waits on a full send
	// window before §9.5's ErrSendQueueFull is returned instead of blocking.
	SendBlockedMS = 2000

	// MidFrameBudgetMSDefault is the default for Client.MidFrameBudgetMS and
	// Server.MidFrameBudgetMS (message layer 8 item 2).
	MidFrameBudgetMSDefault = 10000
)

// PendingSlots is PENDING_SLOTS (§2), the §14.0a default of one slot per allowed
// controller. Concurrent in-flight admissions, tuple-keyed (§6.3).
const PendingSlots = 2

// admissionEpochMax is 2^56: §4.2 keeps admission_epoch's top 8 bits clear, so a
// value at or above this is out of range and §6.2 step 7 fails closed.
const admissionEpochMax = 1 << 56

// pendingRecord is one §6.3 slot. Fixed-size, never heap-allocated per admission;
// the four keys are wiped whenever pendingGeneration advances (§6.3 invariant).
// Each record also carries the session's empty c2s replay window (§8).
type pendingRecord struct {
	used       bool
	tuple      []byte // source_tuple = canonical_source (18)
	finish     []byte // stored FINISH[256] for §6.2 step 2 verbatim resend
	admit      []byte // stored ADMIT[82]
	keys       SessionKeys
	generation uint32       // device-wide-monotonic (§6.3)
	expiry     uint32       // now_ms (32-bit) + PendingTTLMS; smallest = oldest
	c2sWindow  replayWindow // empty c2s replay window (§6.3)
}

func (r *pendingRecord) wipeKeys() {
	for _, k := range [][]byte{r.keys.KC2S, r.keys.KS2C, r.keys.KKcpC2S, r.keys.KKcpS2C} {
		for i := range k {
			k[i] = 0
		}
	}
}

// Device is one responder. Keys derive from the PSK and device_id at
// construction (§0); cookie_secret and admission_epoch are per-boot CSPRNG draws
// the caller supplies (§4.2 — randomness is the caller's, not this package's).
type Device struct {
	DeviceID       []byte // 8 octets
	kDev           []byte // 32, needed by Master (§4.5)
	kReq, kResp    []byte // 32 each
	cookieSecret   []byte // 32, per boot
	admissionEpoch []byte // 8, per boot, top-8-bits-clear nonzero (§4.2)
	local          []netip.Prefix
	// sourceCheck makes HandleINIT/HandleFINISH apply §4.3 source rejection
	// themselves (default on), as C's sn_handle_init/sn_handle_finish do, so an
	// embedder that demultiplexes without Classify still never answers a
	// broadcast, multicast or own-address source. Guarded by rec.
	sourceCheck bool

	// rec is §10.1's rec_lock. It protects ALL record state, which the spec
	// enumerates as: the pending records in full, the primary's metadata (keys,
	// tuple, generation, c2s replay window), the pointer identifying the current
	// primary KCP object, admission_epoch, the promotion generation, and the two
	// cached epoch_tag values.
	//
	// It lives on Device rather than on Server because Device owns most of that
	// state and outlives every session, and because the spec names ONE lock over
	// the whole set — a Server-side mutex covering the primary and an unguarded
	// Device would be two locks over one invariant, which is how the pending
	// table and the primary came to be mutated from different critical sections.
	// Server therefore takes s.dev.rec and has no mutex of its own.
	//
	// Rules, from §10.1 and §10.3: nothing under it transmits, and no
	// verification of an UNAUTHENTICATED datagram — a MAC, an AEAD open, HKDF, a
	// scalar multiplication — runs under it. Bounded work only.
	//
	// Divergence from the spec, deliberate: the C device splits rec_lock from
	// kcp_lock so that §8.5(b)'s allocation happens under the latter. This Go
	// server holds rec across the kcp-go session allocation in promote(). §10.1's
	// "no allocation" exists because rec_lock is a portMUX spinlock on ESP32;
	// this is a plain mutex in an emulator and a controller-side test harness, so
	// the cost is a bounded wait rather than a blocked ISR. The C implementation
	// is the device of record and keeps both locks.
	rec sync.Mutex

	// epoch_tag is cached, not recomputed per datagram (§4.4); RollEpoch
	// advances it and keeps the previous tag (§2). Guarded by rec.
	cookieEpoch  uint32
	epochTag     []byte // 8
	prevEpochTag []byte // 8, nil until the first roll

	pending  [PendingSlots]pendingRecord
	genCtr   uint32 // device-wide pending_generation source (§6.3)
	randFill func([]byte)
}

// ErrBadKeyMaterial reports a constructor input of the wrong width (§0, §4.2):
// psk, k_dev and cookie_secret are 32 octets, device_id and admission_epoch 8.
var ErrBadKeyMaterial = errors.New("shieldnet: key material has the wrong length or value")

// checkLen fails closed on a wrong-width input. A nil or short secret would
// otherwise derive keys anyone can compute (an empty PSK, an empty
// cookie_secret) or panic later inside an encoder.
func checkLen(name string, b []byte, n int) error {
	if len(b) != n {
		return fmt.Errorf("%w: %s is %d octets, want %d", ErrBadKeyMaterial, name, len(b), n)
	}
	return nil
}

// NewDevice derives k_dev from the PSK and builds the device. It exists for
// tests, emulators and demos that hold the fleet PSK anyway. A real device is
// provisioned with k_dev only and never sees the PSK (README "Keys and
// identity"): build it with NewDeviceFromKDev.
//
// local must be the receiving interface's prefixes: without them the
// own-address and subnet-broadcast refusal of transport 7.2 does not happen.
// cookieSecret (32 octets) and admissionEpoch (non-zero, 64 bits, its eight
// most significant bits clear) must be drawn fresh from a cryptographic random
// source at each start, held in volatile memory only, never persisted and
// never derived from the PSK or k_dev (transport 3.4).
func NewDevice(psk, deviceID, cookieSecret, admissionEpoch []byte, local []netip.Prefix, nowMS uint64) (*Device, error) {
	if err := checkLen("psk", psk, 32); err != nil {
		return nil, err
	}
	if allZero(psk) {
		return nil, fmt.Errorf("%w: psk is all zero", ErrBadKeyMaterial)
	}
	if err := checkLen("device_id", deviceID, 8); err != nil {
		return nil, err
	}
	kDev := DeriveKDev(psk, deviceID)
	defer zero(kDev)
	return NewDeviceFromKDev(kDev, deviceID, cookieSecret, admissionEpoch, local, nowMS)
}

// NewDeviceFromKDev builds a device from its provisioned k_dev (§0) and rolls
// the first cookie epoch from nowMS (a 64-bit monotonic-ms clock reading, §2).
// k_dev and cookieSecret are 32 octets; deviceID and admissionEpoch are 8, and
// admissionEpoch must be nonzero with its top 8 bits clear (§4.2). Inputs are
// copied. The ephemeral-key source defaults to crypto/rand; tests may replace it
// via SetRandSource.
//
// local must be the receiving interface's prefixes: without them the
// own-address and subnet-broadcast refusal of transport 7.2 does not happen.
// cookieSecret (32 octets) and admissionEpoch (non-zero, 64 bits, its eight
// most significant bits clear) must be drawn fresh from a cryptographic random
// source at each start, held in volatile memory only, never persisted and
// never derived from the PSK or k_dev (transport 3.4).
func NewDeviceFromKDev(kDev, deviceID, cookieSecret, admissionEpoch []byte, local []netip.Prefix, nowMS uint64) (*Device, error) {
	for _, c := range []struct {
		name string
		b    []byte
		n    int
	}{{"k_dev", kDev, 32}, {"device_id", deviceID, 8}, {"cookie_secret", cookieSecret, 32}, {"admission_epoch", admissionEpoch, 8}} {
		if err := checkLen(c.name, c.b, c.n); err != nil {
			return nil, err
		}
	}
	if allZero(kDev) || allZero(cookieSecret) {
		return nil, fmt.Errorf("%w: k_dev or cookie_secret is all zero", ErrBadKeyMaterial)
	}
	if ae := binary.BigEndian.Uint64(admissionEpoch); ae == 0 || ae >= admissionEpochMax {
		return nil, fmt.Errorf("%w: admission_epoch must be nonzero with its top 8 bits clear", ErrBadKeyMaterial)
	}
	static := DeriveStatic(kDev)
	d := &Device{
		DeviceID:       append([]byte(nil), deviceID...),
		kDev:           append([]byte(nil), kDev...),
		kReq:           static.KReq,
		kResp:          static.KResp,
		cookieSecret:   append([]byte(nil), cookieSecret...),
		admissionEpoch: append([]byte(nil), admissionEpoch...),
		local:          local,
		sourceCheck:    true,
		randFill:       func(b []byte) { _, _ = rand.Read(b) },
	}
	d.RollEpoch(nowMS)
	return d, nil
}

// SetSourceCheck turns the handlers' own §4.3 source rejection on or off. It is
// on by default. Turn it off only for a harness bound to loopback, whose own
// address is the client's (C: sn_device_set_source_check).
func (d *Device) SetSourceCheck(on bool) {
	d.rec.Lock()
	d.sourceCheck = on
	d.rec.Unlock()
}

func (d *Device) sourceRejected(a netip.Addr) bool {
	d.rec.Lock()
	on := d.sourceCheck
	d.rec.Unlock()
	return on && SourceRejected(a, d.local)
}

// Wipe zeroes the device's static keys, cookie secret and every pending
// record's session keys. The device is unusable afterwards. Server.Close calls
// it.
func (d *Device) Wipe() {
	d.rec.Lock()
	defer d.rec.Unlock()
	for i := range d.pending {
		d.pending[i].wipeKeys()
		d.pending[i].used = false
	}
	zero(d.kDev)
	zero(d.kReq)
	zero(d.kResp)
	zero(d.cookieSecret)
	zero(d.epochTag)
	zero(d.prevEpochTag)
}

// SetRandSource overrides the ephemeral-key source (§6.2 step 6). For tests that
// need a deterministic e_s; production keeps crypto/rand.
func (d *Device) SetRandSource(fill func([]byte)) {
	// randFill is read by HandleFINISH on the Serve goroutine, which snapshots it
	// under rec before its unlocked derivation, so this write must take rec too
	// (§10.1 permits it: a pointer store, non-blocking).
	d.rec.Lock()
	d.randFill = fill
	d.rec.Unlock()
}

func be4(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// RollEpoch recomputes the cached epoch_tag when the cookie epoch has advanced,
// keeping the previous tag. §4.4 requires this run on the maintenance tick's
// boundary crossing, never on a receive path. Idempotent within an epoch.
func (d *Device) RollEpoch(nowMS uint64) {
	d.rec.Lock()
	defer d.rec.Unlock()
	d.rollEpochLocked(nowMS)
}

// rollEpochLocked requires rec.
func (d *Device) rollEpochLocked(nowMS uint64) {
	ep := uint32(nowMS / CookieEpochMS)
	if d.epochTag != nil && ep == d.cookieEpoch {
		return
	}
	// Shift the previous tag ONLY across a single-epoch boundary. §2 sizes
	// COOKIE_EPOCH_MS so a suppressed FINISH is useful for at most 8 s; shifting
	// unconditionally after a stalled tick (say 5 -> 9) would leave epoch 5's tag
	// live alongside epoch 9's and accept a capture 16-20 s old.
	if d.epochTag != nil && ep == d.cookieEpoch+1 {
		d.prevEpochTag = d.epochTag
	} else {
		d.prevEpochTag = nil
	}
	d.cookieEpoch = ep
	d.epochTag = EpochTag(d.cookieSecret, be4(ep))
}

// HandleINIT implements §6.1. Returns the RETRY datagram, or nil to drop silently
// (§9.3). src is the datagram's UDP source, used for the cookie's and RETRY's
// observed_source = canonical_source (§4.3). nowMS is the same monotonic-ms
// clock HandleFINISH takes: the cookie is minted under nowMS's epoch, so its
// lifetime is bounded by the clock and not by how often Tick runs (§4.4). No
// state is created.
func (d *Device) HandleINIT(datagram []byte, src netip.AddrPort, nowMS uint64) []byte {
	if d.sourceRejected(src.Addr()) { // §4.3, before any work
		return nil
	}
	return d.handleINIT(datagram, src, nowMS)
}

// handleINIT is HandleINIT after the §4.3 check. Server calls it directly
// because its Classify has already applied that check.
func (d *Device) handleINIT(datagram []byte, src netip.AddrPort, nowMS uint64) []byte {
	// §10.3: the MAC of an UNAUTHENTICATED datagram MUST NOT be verified under
	// rec_lock — that is what stops a flood from holding it. kReq and DeviceID
	// are immutable after construction, so steps 1-3 need no lock at all.
	f, err := DecodeINIT(datagram) // step 1: length + padding (§3.1)
	if err != nil {
		return nil
	}
	if !hmac.Equal(f.DeviceID, d.DeviceID) { // step 2: our device_id, no crypto
		return nil
	}
	want := InitMAC(d.kReq, f.ClientNonce, f.DeviceID) // step 3
	if !hmac.Equal(want, f.InitMAC) {                  // failure: drop, no cookie
		return nil
	}

	epochTag, _ := d.epochTagsAt(nowMS)
	d.rec.Lock()
	admissionEpoch := append([]byte(nil), d.admissionEpoch...)
	d.rec.Unlock()

	cs := Canonicalize(src.Addr(), src.Port()) // step 4
	cookie := Cookie(d.cookieSecret, epochTag, cs, f.ClientNonce)
	retryMAC := RetryMAC(d.kResp, f.ClientNonce, epochTag, cookie, admissionEpoch, d.DeviceID, cs)
	return EncodeRETRY(epochTag, cookie, admissionEpoch, d.DeviceID, cs, retryMAC)
}

// epochTagsAt returns the epoch_tag for nowMS's cookie epoch and, past epoch 0,
// the one before it (§4.4). The cached tags serve the common case; any other
// epoch's tag is computed outside rec (§10.3), so a stalled Tick can neither
// stretch a cookie's life nor reject a fresh one. Mirrors C epoch_tags_at.
func (d *Device) epochTagsAt(nowMS uint64) (cur, prev []byte) {
	ep := uint32(nowMS / CookieEpochMS)
	d.rec.Lock()
	have := d.epochTag != nil
	cEp := d.cookieEpoch
	cTag := append([]byte(nil), d.epochTag...)
	pTag := append([]byte(nil), d.prevEpochTag...)
	d.rec.Unlock()

	if have && cEp == ep {
		cur = cTag
	} else {
		cur = EpochTag(d.cookieSecret, be4(ep))
	}
	if ep > 0 {
		switch {
		case have && cEp == ep-1:
			prev = cTag
		case have && len(pTag) == 8 && cEp == ep:
			prev = pTag // prevEpochTag is only ever cookieEpoch-1's tag
		default:
			prev = EpochTag(d.cookieSecret, be4(ep-1))
		}
	}
	return cur, prev
}

// epochTagKnown reports, in constant time, whether tag is the current or the
// previous epoch_tag as of nowMS (§6.2 step 3).
func epochTagKnown(tag, cur, prev []byte) bool {
	known := hmac.Equal(tag, cur)
	if prev != nil {
		known = hmac.Equal(tag, prev) || known
	}
	return known
}

// findPending returns the slot index holding tuple, or -1.
// Tick is the §9.2 maintenance pass: it rolls the cookie epoch when it has
// advanced and wipes the keys of pending records that have expired. §6.3 calls
// this "what makes the bound real" — expiry is otherwise only evaluated at
// lookup, so a record whose client vanished keeps four live session keys in RAM
// until its slot happens to be reused.
//
// The caller supplies the clock; Server.Serve runs it on a ticker.
func (d *Device) Tick(nowMS uint64) {
	d.rec.Lock()
	defer d.rec.Unlock()
	d.rollEpochLocked(nowMS)
	now32 := uint32(nowMS)
	for i := range d.pending {
		if d.pending[i].used && int32(d.pending[i].expiry-now32) <= 0 {
			d.pending[i].wipeKeys()
			d.pending[i].used = false
		}
	}
}

// findPending requires rec.
func (d *Device) findPending(tuple []byte) int {
	for i := range d.pending {
		if d.pending[i].used && hmac.Equal(d.pending[i].tuple, tuple) {
			return i
		}
	}
	return -1
}

// installSlot chooses the slot to write for tuple: the same-tuple record if one
// exists (replace), else a free slot, else the oldest by expiry (evict). It wipes
// the outgoing record's keys before returning the index (§6.3 invariant).
// installSlot requires rec.
func (d *Device) installSlot(tuple []byte) int {
	if i := d.findPending(tuple); i >= 0 {
		d.pending[i].wipeKeys()
		return i
	}
	for i := range d.pending {
		if !d.pending[i].used {
			return i
		}
	}
	oldest := 0
	for i := 1; i < len(d.pending); i++ {
		if int32(d.pending[i].expiry-d.pending[oldest].expiry) < 0 {
			oldest = i
		}
	}
	d.pending[oldest].wipeKeys()
	return oldest
}

// HandleFINISH implements §6.2 in the mandated order, returning the ADMIT to send
// or nil to drop. nowMS is a monotonic-ms reading for expiry. src is the UDP
// source (its canonical_source is the tuple binding, §6.2 step 3).
func (d *Device) HandleFINISH(datagram []byte, src netip.AddrPort, nowMS uint64) []byte {
	if d.sourceRejected(src.Addr()) { // §4.3, before any work
		return nil
	}
	return d.handleFINISH(datagram, src, nowMS)
}

// handleFINISH is HandleFINISH after the §4.3 check (see handleINIT).
func (d *Device) handleFINISH(datagram []byte, src netip.AddrPort, nowMS uint64) []byte {
	f, err := DecodeFINISH(datagram) // step 1: length + padding (§3.3)
	if err != nil {
		return nil
	}
	tuple := Canonicalize(src.Addr(), src.Port())
	now32 := uint32(nowMS)

	// Under rec_lock: step 2's verbatim-resend check (§6.2 step 2's 256-octet
	// memcmp is one of the two unauthenticated operations §10.1 deliberately
	// takes under the lock) plus a read-out of the mutable epoch state.
	d.rec.Lock()
	if i := d.findPending(tuple); i >= 0 && int32(d.pending[i].expiry-now32) > 0 {
		if hmac.Equal(d.pending[i].finish, datagram) {
			admit := append([]byte(nil), d.pending[i].admit...)
			d.rec.Unlock()
			return admit
		}
	}
	admissionEpoch := append([]byte(nil), d.admissionEpoch...)
	// Snapshot the ephemeral-key source under the lock that SetRandSource takes.
	// Step 6 below runs unlocked, so reading d.randFill there raced with any
	// concurrent SetRandSource — the lock in that setter was guarding a write
	// whose only reader was outside it.
	randFill := d.randFill
	d.rec.Unlock()

	// §10.3: everything below — three MAC verifications, a scalar multiplication
	// and a full key derivation — runs UNLOCKED. A flood of forged FINISHes must
	// not be able to hold rec_lock through an X25519.
	curTag, prevTag := d.epochTagsAt(nowMS)
	if !epochTagKnown(f.EpochTag, curTag, prevTag) { // step 3a
		return nil
	}
	wantCookie := Cookie(d.cookieSecret, f.EpochTag, tuple, f.ClientNonce)
	if !hmac.Equal(wantCookie, f.Cookie) { // step 3b: the tuple binding
		return nil
	}
	if !hmac.Equal(f.AdmissionEpoch, admissionEpoch) { // step 4: single-use
		return nil
	}
	// step 5: client_tag proves the PSK. An invalid FINISH alters no state.
	context := Context(f.ClientNonce, f.EpochTag, f.Cookie, f.AdmissionEpoch, d.DeviceID)
	if !hmac.Equal(ClientTag(d.kReq, context, f.EC), f.ClientTag) {
		return nil
	}

	// step 6: ephemeral pair, DH (reject all-zero), derive — still unlocked.
	esPriv := make([]byte, 32)
	randFill(esPriv)
	esPub, err := curve25519.X25519(esPriv, curve25519.Basepoint)
	if err != nil {
		zero(esPriv)
		return nil
	}
	dh, err := DH(esPriv, f.EC)
	zero(esPriv)    // §4.5: wipe the ephemeral private key as soon as dh is computed
	if err != nil { // all-zero X25519 output (§4.5)
		return nil
	}
	context2 := Context2(context, f.EC, esPub)
	master := Master(context2, d.kDev, dh)
	zero(dh)
	keys := DeriveSession(master)
	admitPre := AdmitPre(d.kResp, context2)
	admitTag := AdmitTag(master)
	zero(master)
	admit := EncodeADMIT(f.AdmissionEpoch, esPub, admitPre, admitTag)

	// step 7: guarded — re-check admission_epoch against the CURRENT value (it
	// may have advanced while the derivation above ran unlocked, which is what
	// keeps it single-use), then commit atomically.
	d.rec.Lock()
	defer d.rec.Unlock()
	if !hmac.Equal(f.AdmissionEpoch, d.admissionEpoch) {
		keys.wipe() // live keys for a session that will never exist
		return nil
	}
	next, ok := incAdmissionEpoch(d.admissionEpoch)
	if !ok { // §4.2 range exhausted → fail closed
		keys.wipe()
		return nil
	}
	i := d.installSlot(tuple)
	d.pending[i] = pendingRecord{
		used:       true,
		tuple:      append([]byte(nil), tuple...),
		finish:     append([]byte(nil), datagram...),
		admit:      append([]byte(nil), admit...),
		keys:       keys,
		generation: d.genCtr,
		expiry:     now32 + PendingTTLMS,
		c2sWindow:  replayWindow{}, // fresh empty window (§6.3)
	}
	d.genCtr++
	d.admissionEpoch = next

	return admit // transmission is outside the guarded region (§10.1)
}

// zero best-effort wipes a byte slice. Go cannot guarantee the runtime kept no
// copy (GC, curve25519 internals), but §4.5's wipe is honoured as far as the
// language allows — and not attempting it would diverge from the C side.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wipe zeroes the four session keys.
func (s SessionKeys) wipe() {
	for _, k := range [][]byte{s.KC2S, s.KS2C, s.KKcpC2S, s.KKcpS2C} {
		for i := range k {
			k[i] = 0
		}
	}
}

// incAdmissionEpoch returns admission_epoch+1 as 8 BE octets, failing closed if
// the result leaves §4.2's top-8-bits-clear range.
func incAdmissionEpoch(ae []byte) ([]byte, bool) {
	v := binary.BigEndian.Uint64(ae) + 1
	if v >= admissionEpochMax {
		return nil, false
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out, true
}
