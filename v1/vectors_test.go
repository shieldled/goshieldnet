// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// The canonical golden-vector file is shieldnet-protocol/vectors/shieldnet-v1-vectors.json,
// generated independently from the spec by shieldnet-protocol/vectors/gen_vectors.py
// (Python stdlib HMAC/HKDF + the cryptography library); testdata/ holds a byte-exact
// copy, checked by TestVectorsMatchSpecRepo. This test makes that file the single
// source of truth: Go must reproduce every value in it. The C suite compiles a header generated from the same file, so a green run on
// both sides is the C<->Go byte-exact agreement §15 requires. Nothing here is
// self-referential — the expected bytes come from a different implementation.
type goldenVectors struct {
	Inputs struct {
		PSK             string `json:"psk"`
		DeviceID        string `json:"device_id"`
		ClientNonce     string `json:"client_nonce"`
		EpochTag        string `json:"epoch_tag"`
		Cookie          string `json:"cookie"`
		AdmissionEpoch  string `json:"admission_epoch"`
		CookieSecret    string `json:"cookie_secret"`
		CookieEpochBE   string `json:"cookie_epoch_be"`
		CanonicalSource string `json:"canonical_source"`
		ObservedSource  string `json:"observed_source"`
		ECPriv          string `json:"e_c_priv"`
		ESPriv          string `json:"e_s_priv"`
		KcpMsg          string `json:"kcp_msg"`
		SeqFull         uint64 `json:"seq_full"`
		PSK2            string `json:"psk2"`
		LowOrderPoint   string `json:"low_order_point"`
		DeviceID2       string `json:"device_id2"`
		KcpConv         uint32 `json:"kcp_conv"`
		KcpPush         string `json:"kcp_push"`
	} `json:"inputs"`
	Schedule  map[string]string `json:"schedule"`
	Messages  map[string]string `json:"messages"`
	WireCases []struct {
		Name     string `json:"name"`
		Role     int    `json:"role"`
		Datagram string `json:"datagram"`
		Cls      int    `json:"cls"`
		Decodes  bool   `json:"decodes"`
	} `json:"wire_cases"`
	SourceLocal []struct {
		Addr string `json:"addr"`
		IsV4 bool   `json:"is_v4"`
		Bits int    `json:"bits"`
	} `json:"source_local"`
	SourceCases []struct {
		Name     string `json:"name"`
		Addr     string `json:"addr"`
		IsV4     bool   `json:"is_v4"`
		Rejected bool   `json:"rejected"`
	} `json:"source_cases"`
	CanonicalSource map[string]string `json:"canonical_source"`
	ReplayScript    []struct {
		Seq    uint64 `json:"seq"`
		Accept bool   `json:"accept"`
		Why    string `json:"why"`
	} `json:"replay_script"`
	Reconstruct []struct {
		SeqWire   uint32 `json:"seq_wire"`
		HWM       uint64 `json:"hwm"`
		Candidate int64  `json:"candidate"`
	} `json:"reconstruct"`
	ReconstructRange []struct {
		Why       string `json:"why"`
		SeqWire   uint32 `json:"seq_wire"`
		HWM       uint64 `json:"hwm"`
		Candidate int64  `json:"candidate"`
		InRange   bool   `json:"in_range"`
	} `json:"reconstruct_range"`
	EnvelopeSize struct {
		WireMTU int `json:"wire_mtu"`
		Cases   []struct {
			Len    int  `json:"len"`
			Accept bool `json:"accept"`
		} `json:"cases"`
	} `json:"envelope_size"`
}

func loadVectors(t *testing.T) *goldenVectors {
	t.Helper()
	b, err := os.ReadFile("../testdata/shieldnet-v1-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v goldenVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func dh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// Go reproduces every schedule vector in the canonical file.
func TestGoldenSchedule(t *testing.T) {
	v := loadVectors(t)
	in := v.Inputs
	psk := dh(t, in.PSK)
	dev := dh(t, in.DeviceID)
	nonce := dh(t, in.ClientNonce)
	etag := dh(t, in.EpochTag)
	cookie := dh(t, in.Cookie)
	aepoch := dh(t, in.AdmissionEpoch)
	cs := dh(t, in.CookieSecret)
	cepoch := dh(t, in.CookieEpochBE)
	canon := dh(t, in.CanonicalSource)
	obs := dh(t, in.ObservedSource)
	ecPriv := dh(t, in.ECPriv)
	esPriv := dh(t, in.ESPriv)

	eC, _ := curve25519.X25519(ecPriv, curve25519.Basepoint)
	eS, _ := curve25519.X25519(esPriv, curve25519.Basepoint)
	kDev := DeriveKDev(psk, dev)
	st := DeriveStatic(kDev)
	ctx := Context(nonce, etag, cookie, aepoch, dev)
	ctx2 := Context2(ctx, eC, eS)
	dhv, err := DH(ecPriv, eS)
	if err != nil {
		t.Fatalf("DH: %v", err)
	}
	master := Master(ctx2, kDev, dhv)
	sk := DeriveSession(master)
	env, err := Seal(sk.KKcpC2S, true, in.SeqFull, dh(t, in.KcpMsg))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got := map[string][]byte{
		"k_dev": kDev, "k_req": st.KReq, "k_resp": st.KResp,
		"e_c": eC, "e_s": eS,
		"epoch_tag_out": EpochTag(cs, cepoch), "cookie_out": Cookie(cs, etag, canon, nonce),
		"init_mac":   InitMAC(st.KReq, nonce, dev),
		"retry_mac":  RetryMAC(st.KResp, nonce, etag, cookie, aepoch, dev, obs),
		"client_tag": ClientTag(st.KReq, ctx, eC), "admit_pre": AdmitPre(st.KResp, ctx2),
		"context": ctx, "context2": ctx2, "dh": dhv, "master": master,
		"k_c2s": sk.KC2S, "k_s2c": sk.KS2C, "k_kcp_c2s": sk.KKcpC2S, "k_kcp_s2c": sk.KKcpS2C,
		"admit_tag": AdmitTag(master), "envelope": env,

		// §15 additions: the Extract stages, the second PSK's and second device's keys, the
		// s2c envelope and the all-zero X25519 verdict.
		"prk_psk":      hkdfExtract(zeroSalt, dh(t, v.Inputs.PSK)),
		"prk_static":   hkdfExtract(zeroSalt, DeriveKDev(dh(t, v.Inputs.PSK), dh(t, v.Inputs.DeviceID))),
		"k_dev_psk2":   DeriveKDev(dh(t, v.Inputs.PSK2), dh(t, v.Inputs.DeviceID)),
		"k_dev_dev2":   DeriveKDev(dh(t, v.Inputs.PSK), dh(t, v.Inputs.DeviceID2)),
		"envelope_s2c": sealOrFail(t, dh(t, v.Schedule["k_kcp_s2c"]), false, v.Inputs.SeqFull, dh(t, v.Inputs.KcpMsg)),
		"dh_low_order": lowOrderDH(t, dh(t, v.Inputs.ECPriv), dh(t, v.Inputs.LowOrderPoint)),
		// transport Appendix A: the first client-to-device KCP push, at seq_full 1.
		"envelope_push": sealOrFail(t, dh(t, v.Schedule["k_kcp_c2s"]), true, 1, dh(t, v.Inputs.KcpPush)),
	}
	// Every schedule entry in the file must be produced by Go, and Go must produce
	// nothing the file omits (catches a vector added on one side only).
	for name, wantHex := range v.Schedule {
		g, ok := got[name]
		if !ok {
			t.Errorf("vector %q in file has no Go producer", name)
			continue
		}
		if !bytes.Equal(g, dh(t, wantHex)) {
			t.Errorf("%s\n  got  %x\n  want %s", name, g, wantHex)
		}
	}
	if len(got) != len(v.Schedule) {
		t.Errorf("Go produces %d values, file has %d — a vector is missing on one side", len(got), len(v.Schedule))
	}

	// The four encoded messages, built from the same fixed fields.
	initMAC := dh(t, v.Schedule["init_mac"])
	retryMAC := dh(t, v.Schedule["retry_mac"])
	clientTag := dh(t, v.Schedule["client_tag"])
	admitPre := dh(t, v.Schedule["admit_pre"])
	admitTag := dh(t, v.Schedule["admit_tag"])
	msgs := map[string][]byte{
		"init":   EncodeINIT(nonce, dev, initMAC),
		"retry":  EncodeRETRY(etag, cookie, aepoch, dev, obs, retryMAC),
		"finish": EncodeFINISH(nonce, etag, cookie, aepoch, eC, clientTag),
		"admit":  EncodeADMIT(aepoch, eS, admitPre, admitTag),
	}
	for name, wantHex := range v.Messages {
		if !bytes.Equal(msgs[name], dh(t, wantHex)) {
			t.Errorf("message %s\n  got  %x\n  want %s", name, msgs[name], wantHex)
		}
	}
}

// Reconstruction cases from the canonical file.
func TestGoldenReconstruct(t *testing.T) {
	for _, c := range loadVectors(t).Reconstruct {
		if got := Reconstruct(c.SeqWire, c.HWM); got != c.Candidate {
			t.Errorf("Reconstruct(%#x, %d) = %d, want %d", c.SeqWire, c.HWM, got, c.Candidate)
		}
	}
}

// transport 11.5: reconstruction and the range rule together, including the
// boundary exactly REPLAY_WINDOW below the high-water mark.
func TestGoldenReconstructRange(t *testing.T) {
	v := loadVectors(t)
	if len(v.ReconstructRange) == 0 {
		t.Fatal("no reconstruct_range cases in the vector file")
	}
	for _, c := range v.ReconstructRange {
		got := Reconstruct(c.SeqWire, c.HWM)
		if got != c.Candidate {
			t.Errorf("%s: Reconstruct(%#x, %d) = %d, want %d", c.Why, c.SeqWire, c.HWM, got, c.Candidate)
		}
		if r := inRange(c.Candidate, c.HWM); r != c.InRange {
			t.Errorf("%s: inRange(%d, %d) = %v, vector says %v", c.Why, c.Candidate, c.HWM, r, c.InRange)
		}
	}
}

// transport 5.7: KCP_OVERHEAD + ENVELOPE_LEN <= N <= WIRE_MTU.
func TestGoldenEnvelopeSize(t *testing.T) {
	es := loadVectors(t).EnvelopeSize
	if es.WireMTU != WireMTU {
		t.Errorf("wire_mtu %d, WireMTU %d", es.WireMTU, WireMTU)
	}
	if len(es.Cases) == 0 {
		t.Fatal("no envelope_size cases in the vector file")
	}
	for _, c := range es.Cases {
		if got := envelopeLenOK(c.Len); got != c.Accept {
			t.Errorf("len %d: accept=%v, vector says %v", c.Len, got, c.Accept)
		}
	}
}

// transport Appendix A: envelope_push opens under k_kcp_c2s at seq_full 1 to a
// KCP PUSH that passes the promotion check (cmd PUSH, sn 0) on inputs.kcp_conv.
func TestGoldenEnvelopePush(t *testing.T) {
	v := loadVectors(t)
	env := dh(t, v.Schedule["envelope_push"])
	pt, err := Open(dh(t, v.Schedule["k_kcp_c2s"]), true, 1, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, dh(t, v.Inputs.KcpPush)) {
		t.Fatalf("opened\n got %x\nwant %s", pt, v.Inputs.KcpPush)
	}
	if pt[4] != kcpCmdPush {
		t.Errorf("cmd %d, want PUSH %d", pt[4], kcpCmdPush)
	}
	if sn := binary.LittleEndian.Uint32(pt[12:16]); sn != 0 {
		t.Errorf("sn %d, want 0", sn)
	}
	if !isPromotingSegment(pt) {
		t.Error("the server's promotion check refuses the vector's first segment")
	}
	if conv := binary.LittleEndian.Uint32(pt[0:4]); conv != v.Inputs.KcpConv {
		t.Errorf("conv %#x, want %#x", conv, v.Inputs.KcpConv)
	}
	if !envelopeLenOK(len(env)) {
		t.Errorf("envelope_push length %d fails the 5.7 length rule", len(env))
	}
}

// §8.5 (a)3: only a KCP PUSH with sn 0, at least KcpOverhead long, promotes.
func TestPromotingSegmentRule(t *testing.T) {
	v := loadVectors(t)
	env := dh(t, v.Schedule["envelope_push"])
	pt, err := Open(dh(t, v.Schedule["k_kcp_c2s"]), true, 1, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !isPromotingSegment(pt) {
		t.Fatal("the vector's first segment is refused")
	}
	sn1 := append([]byte(nil), pt...)
	binary.LittleEndian.PutUint32(sn1[12:16], 1)
	ack := append([]byte(nil), pt...)
	ack[4] = 82
	for name, p := range map[string][]byte{"sn 1": sn1, "cmd ACK": ack, "short": pt[:KcpOverhead-1]} {
		if isPromotingSegment(p) {
			t.Errorf("%s: accepted, want refused", name)
		}
	}
}

func sealOrFail(t *testing.T, key []byte, c2s bool, seq uint64, msg []byte) []byte {
	t.Helper()
	b, err := Seal(key, c2s, seq, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return b
}

// lowOrderDH returns the all-zero output §4.5 defines as the rejection verdict.
// DH refuses the point; the vector pins WHAT both implementations must agree the
// output is, so neither can quietly accept a different one.
func lowOrderDH(t *testing.T, priv, point []byte) []byte {
	t.Helper()
	if _, err := DH(priv, point); err == nil {
		t.Error("DH accepted a low-order point; §4.5 requires rejection")
	}
	return make([]byte, 32)
}

// §4.3 — the accept/reject table §15 calls for. This is the gap that let a
// shipped Critical through: the source predicate silently rejected every IPv4
// controller and the vectors, the fuzzer and the C oracle were all blind to it,
// because none of them ever supplied an IPv6 or v4-mapped source.
func TestGoldenSourceRejection(t *testing.T) {
	v := loadVectors(t)
	local := make([]netip.Prefix, 0, len(v.SourceLocal))
	for _, p := range v.SourceLocal {
		local = append(local, netip.PrefixFrom(vecAddr(t, p.Addr, p.IsV4), p.Bits))
	}
	if len(v.SourceCases) == 0 {
		t.Fatal("no source cases in the vector file")
	}
	for _, c := range v.SourceCases {
		if got := SourceRejected(vecAddr(t, c.Addr, c.IsV4), local); got != c.Rejected {
			t.Errorf("%s (%s): rejected=%v, vector says %v", c.Name, c.Addr, got, c.Rejected)
		}
	}
}

// §4.3 — canonical_source pins RFC 4291 §2.5.5.2's mapped form and the port
// encoding, neither of which any vector covered.
func TestGoldenCanonicalSource(t *testing.T) {
	v := loadVectors(t)
	v4 := Canonicalize(netip.MustParseAddr("192.168.4.2"), 5000)
	if !bytes.Equal(v4, dh(t, v.CanonicalSource["v4"])) {
		t.Errorf("canonical_source v4:\n  got  %x\n  want %s", v4, v.CanonicalSource["v4"])
	}
	v6 := Canonicalize(netip.MustParseAddr("fe80::2"), 5000)
	if !bytes.Equal(v6, dh(t, v.CanonicalSource["v6"])) {
		t.Errorf("canonical_source v6:\n  got  %x\n  want %s", v6, v.CanonicalSource["v6"])
	}
}

// §8.2/§8.3 — the replay window's edges, applied as one scripted sequence to a
// fresh window. Includes the offset-255/256 boundary, which §8.3's range check
// and the window itself deliberately treat differently: a candidate exactly
// REPLAY_WINDOW below hwm passes reconstruction ("more than REPLAY_WINDOW below"
// is the reject rule) and is then dropped by the 256-bit window. Both drop it;
// pinning it stops C and Go drifting on which check does.
func TestGoldenReplayScript(t *testing.T) {
	v := loadVectors(t)
	if len(v.ReplayScript) == 0 {
		t.Fatal("no replay script in the vector file")
	}
	var w replayWindow
	for i, op := range v.ReplayScript {
		if got := w.testAndMark(op.Seq); got != op.Accept {
			t.Errorf("op %d (seq %d, %s): accept=%v, vector says %v",
				i, op.Seq, op.Why, got, op.Accept)
		}
	}
}

func vecAddr(t *testing.T, hexAddr string, isV4 bool) netip.Addr {
	t.Helper()
	b := dh(t, hexAddr)
	if len(b) != 16 {
		t.Fatalf("address %q is %d bytes, want 16", hexAddr, len(b))
	}
	if isV4 {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return netip.AddrFrom16([16]byte(b))
}

// §3/§5 — classification and decode acceptance for malformed and hostile
// datagrams, walked identically by the C suite. The 10-octet cases are the ones
// §3.5 says exist to pin an out-of-bounds read: they classify by type and must
// then be refused on length, without any field being touched.
func TestGoldenWireCases(t *testing.T) {
	v := loadVectors(t)
	if len(v.WireCases) == 0 {
		t.Fatal("no wire cases in the vector file")
	}
	for _, c := range v.WireCases {
		d := dh(t, c.Datagram)
		if got := int(classifyDatagram(Role(c.Role), d)); got != c.Cls {
			t.Errorf("%s: class=%d, vector says %d", c.Name, got, c.Cls)
		}
		var err error
		switch Class(c.Cls) {
		case ClassINIT:
			_, err = DecodeINIT(d)
		case ClassRETRY:
			_, err = DecodeRETRY(d)
		case ClassFINISH:
			_, err = DecodeFINISH(d)
		case ClassADMIT:
			_, err = DecodeADMIT(d)
		default:
			continue // drop/envelope have no type decoder
		}
		if (err == nil) != c.Decodes {
			t.Errorf("%s: decodes=%v (err %v), vector says %v",
				c.Name, err == nil, err, c.Decodes)
		}
	}
}
