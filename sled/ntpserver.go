// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// NTP_SERVER address types.
const (
	ntpAddrName = 1
	ntpAddrIPv4 = 4
	ntpAddrIPv6 = 6
)

const ntpNameMax = 253

// NTPServer is the address a controller announces. An IP literal travels
// in binary; anything else is a host name.
type NTPServer struct {
	Host string
	Port uint16
}

func ntpNameOK(name string) bool {
	if len(name) < 1 || len(name) > ntpNameMax {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// EncodeNTPServer builds an NTP_SERVER payload:
// [u8 addr_type][u8 len][be16 port][address].
func EncodeNTPServer(s NTPServer) ([]byte, error) {
	if s.Port == 0 {
		return nil, errors.New("sled: NTP_SERVER port must be 1 to 65535")
	}
	if s.Host == "" {
		return nil, errors.New("sled: NTP_SERVER host is empty")
	}
	var typ byte
	var addr []byte
	if a, err := netip.ParseAddr(s.Host); err == nil {
		if a.Zone() != "" {
			return nil, fmt.Errorf("sled: NTP_SERVER address %q has a zone", s.Host)
		}
		if a.Is4In6() {
			a = a.Unmap()
		}
		if a.Is4() {
			b := a.As4()
			typ, addr = ntpAddrIPv4, b[:]
		} else {
			b := a.As16()
			typ, addr = ntpAddrIPv6, b[:]
		}
	} else {
		if !ntpNameOK(s.Host) {
			return nil, fmt.Errorf("sled: NTP_SERVER host name %q is not 1 to %d letters, digits, '.' and '-'",
				s.Host, ntpNameMax)
		}
		typ, addr = ntpAddrName, []byte(s.Host)
	}
	b := make([]byte, 4+len(addr))
	b[0] = typ
	b[1] = byte(len(addr))
	binary.BigEndian.PutUint16(b[2:], s.Port)
	copy(b[4:], addr)
	return b, nil
}

// DecodeNTPServer applies the device's rules to an NTP_SERVER payload. Bytes
// after the address are ignored.
func DecodeNTPServer(p []byte) (NTPServer, error) {
	if len(p) < 4 || len(p) < 4+int(p[1]) {
		return NTPServer{}, ErrShort
	}
	typ, n := p[0], int(p[1])
	port := binary.BigEndian.Uint16(p[2:])
	if port == 0 {
		return NTPServer{}, errors.New("sled: NTP_SERVER port is 0")
	}
	addr := p[4 : 4+n]
	switch {
	case typ == ntpAddrIPv4 && n == 4:
		return NTPServer{Host: netip.AddrFrom4([4]byte(addr)).String(), Port: port}, nil
	case typ == ntpAddrIPv6 && n == 16:
		return NTPServer{Host: netip.AddrFrom16([16]byte(addr)).String(), Port: port}, nil
	case typ == ntpAddrName:
		if !ntpNameOK(string(addr)) {
			return NTPServer{}, errors.New("sled: NTP_SERVER host name is not valid")
		}
		return NTPServer{Host: string(addr), Port: port}, nil
	}
	return NTPServer{}, fmt.Errorf("sled: NTP_SERVER addr_type %d with len %d is not defined", typ, n)
}
