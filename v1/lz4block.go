// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0 AND BSD-2-Clause
//
// The decoder below is derived from LZ4's lz4.c (LZ4_decompress_generic and
// read_variable_length, https://github.com/lz4/lz4), translated to Go and
// reduced to the safe, whole-block path. That code is:
//
//   LZ4 - Fast LZ compression algorithm
//   Copyright (C) 2011-2023, Yann Collet.
//   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//       * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package v1

import (
	"encoding/binary"
	"errors"
)

// This file is the receive path's LZ4 block decoder. It accepts and rejects
// exactly the blocks reference LZ4_decompress_safe does (as libshieldnet's
// decompress_lz4 calls it: no dictionary, output size known, whole-block
// decode), so a frame never delivers on one implementation and is refused on
// the other. pierrec/lz4's UncompressBlock skips the end-of-block parsing
// restrictions (last 5 bytes are literals, no match starts in the last 12)
// and refuses a final literals-only sequence whose token has a nonzero match
// nibble, which the reference ignores. Compression still uses pierrec: its
// output is conformant.

var errLZ4Block = errors.New("shieldnet: malformed LZ4 block")

const (
	lz4MinMatch     = 4
	lz4LastLiterals = 5  // LASTLITERALS: the last 5 bytes are always literals
	lz4MFLimit      = 12 // MFLIMIT: no match may start in the last 12 bytes
)

// lz4ReadVarLen mirrors reference read_variable_length: it reads 255-run
// length bytes from src at *ip, failing once *ip passes limit (an index into
// src, exclusive of what may be consumed). initialCheck also fails when no
// byte is available at all.
func lz4ReadVarLen(src []byte, ip *int, limit int, initialCheck bool) (int, bool) {
	if initialCheck && *ip >= limit {
		return 0, false
	}
	n := 0
	for {
		if *ip >= len(src) {
			return 0, false
		}
		s := int(src[*ip])
		*ip++
		n += s
		if *ip > limit || n > 1<<30 {
			return 0, false
		}
		if s != 255 {
			return n, true
		}
	}
}

// lz4DecodeBlock decodes one raw LZ4 block into exactly origSize bytes.
func lz4DecodeBlock(src []byte, origSize int) ([]byte, error) {
	if len(src) == 0 || origSize <= 0 {
		return nil, errLZ4Block
	}
	dst := make([]byte, origSize)
	iend, oend := len(src), origSize
	ip, op := 0, 0
	for {
		if ip >= iend {
			return nil, errLZ4Block
		}
		token := int(src[ip])
		ip++

		// Literals.
		ll := token >> 4
		if ll == 15 {
			addl, ok := lz4ReadVarLen(src, &ip, iend-15, true)
			if !ok {
				return nil, errLZ4Block
			}
			ll += addl
		}
		cpy := op + ll
		if cpy > oend-lz4MFLimit || ip+ll > iend-(2+1+lz4LastLiterals) {
			// The last sequence: its literals must end the input exactly and
			// fit the output; its token's match nibble is never read.
			if ip+ll != iend || cpy > oend {
				return nil, errLZ4Block
			}
			copy(dst[op:], src[ip:ip+ll])
			op = cpy
			break
		}
		copy(dst[op:], src[ip:ip+ll])
		ip += ll
		op = cpy

		// Match.
		offset := int(binary.LittleEndian.Uint16(src[ip:]))
		ip += 2
		ml := token & 15
		if ml == 15 {
			addl, ok := lz4ReadVarLen(src, &ip, iend-lz4LastLiterals+1, false)
			if !ok {
				return nil, errLZ4Block
			}
			ml += addl
		}
		ml += lz4MinMatch
		match := op - offset
		if match < 0 {
			return nil, errLZ4Block // offset reaches before the block
		}
		if op+ml > oend-lz4LastLiterals {
			return nil, errLZ4Block // the last 5 bytes must be literals
		}
		if offset == 0 {
			// The reference copies the not-yet-written output onto itself;
			// for a fresh buffer that is zeros. Reproduce it rather than
			// diverge on a block no conformant encoder emits.
			for i := 0; i < ml; i++ {
				dst[op+i] = 0
			}
		} else {
			for i := 0; i < ml; i++ { // byte-wise: overlap is the point
				dst[op+i] = dst[match+i]
			}
		}
		op += ml
	}
	if op != origSize {
		return nil, errLZ4Block
	}
	return dst, nil
}
