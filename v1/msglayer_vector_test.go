// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// The message layer's golden vectors are Appendix A of spec/message-layer.md in
// shieldnet-protocol; testdata/shieldnet-msglayer-vectors.json is a byte-exact
// copy of the spec repo's vectors/shieldnet-msglayer-vectors.json, checked by
// TestVectorsMatchSpecRepo. The interop tests that would catch a framing
// regression (app_interop_test.go, cinterop_test.go) skip unless SN_HOST_BIN /
// SLED_HOST_BIN point at a built C binary, which CI never sets, so these tests
// are what keep moving MessageNum inside the nonce, reordering the header, or
// dropping the header from the AAD from passing `go test` green.
//
// TestAppFrameMatchesSpec also builds a frame from the SPEC TEXT — message layer
// §5 (header layout, "the 20-byte header is the AEAD additional authenticated
// data") and the nonce (8 zero bytes || BE(MessageNum) || 8 zero bytes) — using
// chacha20poly1305 directly, and compares that against what frameAppWith
// produces. The `plain` vector then pins the construction itself, so that
// editing both the implementation and the reimplementation in the same way is
// still caught.

type msgLayerVectors struct {
	Key   string `json:"key"`
	Cases []struct {
		Name        string `json:"name"`
		MessageType string `json:"message_type"`
		MessageNum  string `json:"message_num"`
		Plaintext   string `json:"plaintext"`
		Frame       string `json:"frame"`
	} `json:"cases"`
}

func loadMsgLayerVectors(t *testing.T) *msgLayerVectors {
	t.Helper()
	b, err := os.ReadFile("../testdata/shieldnet-msglayer-vectors.json")
	if err != nil {
		t.Fatalf("read message-layer vectors: %v", err)
	}
	var v msgLayerVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse message-layer vectors: %v", err)
	}
	return &v
}

// plainVectorFrame is the `plain` case's frame, the parameters of vecParams.
func plainVectorFrame(t *testing.T) string {
	t.Helper()
	for _, c := range loadMsgLayerVectors(t).Cases {
		if c.Name == "plain" {
			return c.Frame
		}
	}
	t.Fatal("no plain case in the message-layer vector file")
	return ""
}

func vecParams() (key, payload []byte, num uint64, msgType uint32) {
	key = make([]byte, 32)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	return key, []byte("shieldnet message layer golden vector payload"),
		0x0102030405060708, 0x00112233
}

// specFrame is an independent implementation of §5's send path, written from the
// document rather than from appframe.go. It deliberately shares no helper with
// the code under test: appHeader and appNonce are exactly what it is checking.
func specFrame(t *testing.T, key, payload []byte, num uint64, msgType uint32) []byte {
	t.Helper()
	// §5: offset 0 Size (ciphertext + 16-byte tag), 4 OriginalSize, 8 MessageType,
	// 12 MessageNum, all big-endian.
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint32(hdr[0:], uint32(len(payload))+16)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[8:], msgType)
	binary.BigEndian.PutUint64(hdr[12:], num)
	// §6: nonce[0:8] = 0, nonce[8:16] = BE(MessageNum), nonce[16:24] = 0.
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint64(nonce[8:16], num)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	// §5 step 3: AAD is the 20-byte header.
	return append(hdr, aead.Seal(nil, nonce, payload, hdr)...)
}

// TestAppFrameMatchesSpec pins the header layout, the nonce layout and the choice
// of AAD together: any one of the three moving changes these bytes.
func TestAppFrameMatchesSpec(t *testing.T) {
	key, payload, num, msgType := vecParams()

	want := specFrame(t, key, payload, num, msgType)
	if got, vec := hex.EncodeToString(want), plainVectorFrame(t); got != vec {
		t.Fatalf("the spec construction itself changed:\n got %s\nwant %s", got, vec)
	}

	got, err := frameAppWith(key, num, msgType, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frameAppWith diverges from shieldnet-message-layer §5/§6:\n got %x\nwant %x", got, want)
	}
}

// TestAppFrameHeaderFieldOffsets asserts each header field at its own offset, so
// a transposition of two same-width fields — which a round-trip cannot see — is
// caught. §5's table is the authority for every constant here.
func TestAppFrameHeaderFieldOffsets(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	payload := bytes.Repeat([]byte{0xEE}, 300)
	const num = uint64(0xDEADBEEFCAFEF00D)
	const msgType = uint32(0x40302010)

	f, err := frameAppWith(key, num, msgType, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 20+len(payload)+16 {
		t.Fatalf("frame length %d, want %d", len(f), 20+len(payload)+16)
	}
	for _, c := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"Size@0", uint64(binary.BigEndian.Uint32(f[0:4])), uint64(len(payload) + 16)},
		{"OriginalSize@4", uint64(binary.BigEndian.Uint32(f[4:8])), uint64(len(payload))},
		{"MessageType@8", uint64(binary.BigEndian.Uint32(f[8:12])), uint64(msgType)},
		{"MessageNum@12", binary.BigEndian.Uint64(f[12:20]), num},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}

	// §5: the header is the AAD. Flipping any header byte must make the frame
	// unopenable — a receiver that passed nil AAD, or only part of the header,
	// would still open some of these.
	for i := 0; i < 20; i++ {
		bad := append([]byte(nil), f...)
		bad[i] ^= 0x80
		var rx uint64
		if _, _, _, err := recvAppWith(bytes.NewReader(bad), key, &rx, &rxStage{}, MaxAppPayload, 0, MaxAppPayload); err == nil {
			t.Errorf("header byte %d is not covered by the AAD", i)
		}
	}
}

// TestAppFrameNonceIsMessageNumBound is the property behind §6's nonce rule: two
// messages that differ ONLY in MessageNum must not share a keystream. Moving
// MessageNum out of the nonce (into an all-zero nonce, say) leaves both frames
// with the same ciphertext for the same plaintext, which is the exact failure
// that reuses a (key, nonce) pair.
func TestAppFrameNonceIsMessageNumBound(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	payload := []byte("identical plaintext under one key")

	a, err := frameAppWith(key, 1, 7, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := frameAppWith(key, 2, 7, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[20:], b[20:]) {
		t.Fatal("MessageNum 1 and 2 produced the same ciphertext: the nonce does not depend on MessageNum")
	}

	// And the dependency is on the value, not merely on some counter: a frame
	// sealed with num N opens only under the nonce derived from that same N.
	var rx uint64
	if _, gotNum, pt, err := recvAppWith(bytes.NewReader(b), key, &rx, &rxStage{}, MaxAppPayload, 0, MaxAppPayload); err != nil {
		t.Fatal(err)
	} else if gotNum != 2 || !bytes.Equal(pt, payload) {
		t.Fatalf("round trip: num %d, payload %q", gotNum, pt)
	}
}

// TestMsgLayerVectors walks every case of message-layer Appendix A: the sender
// reproduces each frame it may emit byte for byte, and the receiver opens every
// frame to the case's plaintext, number and type. compressed-decode is
// receive-only: LZ4 encoders differ, and its block is not shorter than its
// plaintext, so a conforming sender never emits it (message layer 6.1, A.4).
func TestMsgLayerVectors(t *testing.T) {
	v := loadMsgLayerVectors(t)
	key := dh(t, v.Key)
	if len(v.Cases) == 0 {
		t.Fatal("no cases in the message-layer vector file")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			mt, err := strconv.ParseUint(c.MessageType, 16, 32)
			if err != nil {
				t.Fatalf("message_type %q: %v", c.MessageType, err)
			}
			num, err := strconv.ParseUint(c.MessageNum, 16, 64)
			if err != nil {
				t.Fatalf("message_num %q: %v", c.MessageNum, err)
			}
			pt := dh(t, c.Plaintext)
			frame := dh(t, c.Frame)

			var send, pad bool
			switch c.Name {
			case "plain":
				send = true
			case "padded", "padded-45":
				send, pad = true, true
			case "compressed-decode":
			default:
				t.Fatalf("case %q is not handled by this test", c.Name)
			}
			if send {
				got, err := frameAppWith(key, num, uint32(mt), pt, false, pad, MaxAppPayload)
				if err != nil {
					t.Fatalf("frameAppWith: %v", err)
				}
				if !bytes.Equal(got, frame) {
					t.Errorf("frameAppWith\n got %x\nwant %x", got, frame)
				}
			}

			var rx uint64
			gotType, gotNum, gotPT, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, MaxAppPayload, 0, MaxAppPayload)
			if err != nil {
				t.Fatalf("recvAppWith: %v", err)
			}
			if wantType := uint32(mt) &^ FlagCompressed; gotType != wantType {
				t.Errorf("type %#x, want %#x", gotType, wantType)
			}
			if gotNum != num {
				t.Errorf("num %#x, want %#x", gotNum, num)
			}
			if !bytes.Equal(gotPT, pt) {
				t.Errorf("plaintext\n got %x\nwant %x", gotPT, pt)
			}
		})
	}
}
