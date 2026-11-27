// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package secret loads the examples' 32-byte keys (the PSK, a device's k_dev)
// without ever taking them from the command line.
//
// argv is world-readable: ps and /proc/<pid>/cmdline show it to every local
// user. So a key comes from a file named by an environment variable — refused
// unless only its owner can read it — or, failing that, from an environment
// variable holding the hex itself. This is the same UX as libshieldnet's host
// tools (host/sn_host.c, host/sn_client_host.c), except that a group- or
// world-readable key file is refused here rather than warned about.
package secret

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// KeyLen is the width of every key this package loads.
const KeyLen = 32

// ErrNotSet reports that neither the file variable nor the hex variable is set.
var ErrNotSet = errors.New("not set")

// Wipe zeroes b. Go gives no guarantee that no other copy exists (the runtime
// may have moved or copied it), so this is hygiene, not a proof of erasure.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Load returns the 32-byte key from the file named by $fileEnv (64 hex chars,
// trailing whitespace allowed), or else from $hexEnv. It returns ErrNotSet
// (wrapped) when neither is set. The hex variable is unset after it is read so
// that it is not inherited by any child process; the Go string itself cannot be
// wiped.
func Load(fileEnv, hexEnv string) ([]byte, error) {
	if path := os.Getenv(fileEnv); path != "" {
		return loadFile(fileEnv, path)
	}
	v := os.Getenv(hexEnv)
	if v == "" {
		return nil, fmt.Errorf("%s / %s: %w", fileEnv, hexEnv, ErrNotSet)
	}
	_ = os.Unsetenv(hexEnv)
	return decode(hexEnv, []byte(v))
}

func loadFile(fileEnv, path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileEnv, err)
	}
	defer f.Close()
	// fstat on the open descriptor, not stat on the path, so the file checked
	// is the file read.
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileEnv, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %s is not a regular file", fileEnv, path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s: %s has mode %04o and is readable by group/other; "+
			"chmod 600 it", fileEnv, path, perm)
	}
	// 64 hex chars plus a little trailing whitespace; anything longer is not a key.
	buf := make([]byte, 130)
	defer Wipe(buf)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", fileEnv, err)
	}
	if n == len(buf) {
		return nil, fmt.Errorf("%s: %s is too long for a %d-byte hex key", fileEnv, path, KeyLen)
	}
	return decode(fileEnv, buf[:n])
}

// decode parses exactly 2*KeyLen hex chars after trimming trailing whitespace.
func decode(src string, b []byte) ([]byte, error) {
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			break
		}
		b = b[:len(b)-1]
	}
	if len(b) != 2*KeyLen {
		return nil, fmt.Errorf("%s: want exactly %d hex chars, got %d", src, 2*KeyLen, len(b))
	}
	key := make([]byte, KeyLen)
	if _, err := hex.Decode(key, b); err != nil {
		Wipe(key)
		return nil, fmt.Errorf("%s: not hex", src) // the error would quote key material
	}
	return key, nil
}

// RefuseArgv is the error for a key passed on the command line.
func RefuseArgv(flagName, fileEnv, hexEnv string) error {
	return fmt.Errorf("-%s is no longer accepted: a key on the command line is visible "+
		"to every local user through ps and /proc/<pid>/cmdline. Put the hex in a "+
		"mode-0600 file named by %s, or in %s", flagName, fileEnv, hexEnv)
}
