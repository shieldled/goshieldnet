// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package discovery finds sled devices on the local network over mDNS.
//
// Answers arrive as unicast to an ephemeral port (hashicorp/mdns cannot query
// from port 5353), so a stateful host firewall that allows mDNS only by port
// 5353 must also accept inbound UDP from LAN source port 5353.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"

	"github.com/shieldled/goshieldnet/sledclient"
)

// ServiceTypes are the mDNS service types sled devices advertise, and the ones
// DiscoverAll browses. _sled_x1._udp is reserved by spec/application.md section 8;
// it is browsed for this project's host agents, which advertise it. To browse
// other types, such as a custom device's own, set Options.Services rather than
// changing this variable.
var ServiceTypes = []string{"_sled_x1._udp", "_sled_l1._udp", "_sled_s1._udp"}

// ErrBadService is returned, wrapped, by DiscoverAllWith for an Options.Services
// entry that is not of the form "_<name>._udp".
var ErrBadService = errors.New("discovery: bad service type")

// Found is one device seen on the network.
type Found struct {
	Instance    string // mDNS instance (the device UUID on ShieldLED devices)
	Service     string // e.g. "_sled_l1._udp"
	Host        string // IPv4 address; with Options.IPv6, an IPv6 address when the entry has no IPv4, with "%zone" for a link-local one (a dual-stack device may then be listed by either address, depending on which interface's answer arrives first)
	Port        int
	TXT         map[string]string // "k=v" items; a key without "=" maps to ""
	DeviceID    [8]byte           // from Instance (sledclient.DeviceIDFromInstance); zero when HasDeviceID is false
	HasDeviceID bool
}

// Addr is Host and Port as host:port.
func (f Found) Addr() string { return net.JoinHostPort(f.Host, strconv.Itoa(f.Port)) }

// DiscoverAll browses every ServiceTypes entry on every usable interface for
// the whole timeout and returns each unique device (by service+instance).
// Order is per service and per interface, not global arrival order.
//
// If at least one query succeeded, the merged results are returned with a nil
// error; the error is non-nil only when every query failed.
//
// It queries over IPv4 only and lists only devices with an IPv4 address; see
// DiscoverAllWith for IPv6.
func DiscoverAll(timeout time.Duration) ([]Found, error) {
	return DiscoverAllWith(timeout, Options{})
}

// Options tunes DiscoverAllWith. The zero value is DiscoverAll's behaviour.
type Options struct {
	// IPv6 also queries over IPv6, on interfaces with any unicast address, and
	// lists a device that has only an IPv6 address (Found.Host).
	IPv6 bool

	// Services, when not empty, are the mDNS service types to browse instead of
	// ServiceTypes, such as a custom device's own: each "_<name>._udp" without
	// ".local", the name 1 to 15 letters, digits, '-' or '_'. Found.Service is
	// the entry a device was found under. A malformed entry makes DiscoverAllWith
	// return an error wrapping ErrBadService before anything is sent.
	Services []string
}

// DiscoverAllWith is DiscoverAll with options.
func DiscoverAllWith(timeout time.Duration, opts Options) ([]Found, error) {
	services, err := servicesFor(opts)
	if err != nil {
		return nil, err
	}
	ifaces := queryInterfaces(opts.IPv6)

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		seen = map[string]bool{}
		out  []Found
		errs []error
		ok   bool
	)
	query := func(service string, iface *net.Interface) {
		defer wg.Done()
		// Buffered: hashicorp/mdns drops an entry it cannot hand over at once.
		ch := make(chan *mdns.ServiceEntry, 32)

		// A delivered entry is still being written by the query until it
		// returns, so the consumer only keeps the pointers while draining and
		// dereferences none of them before ch is closed. It never stops
		// draining early.
		var entries []*mdns.ServiceEntry
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for e := range ch {
				entries = append(entries, e)
			}
		}()

		params := mdns.DefaultParams(service)
		params.Entries = ch
		params.Interface = iface
		params.Timeout = timeout
		params.WantUnicastResponse = true
		params.DisableIPv6 = !opts.IPv6
		params.Logger = log.New(io.Discard, "", 0)
		// No deadline context: params.Timeout alone bounds the query.
		err := mdns.QueryContext(context.Background(), params)
		close(ch)
		<-drained

		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		ok = true
		for _, e := range entries {
			out = collect(seen, out, service, e, opts.IPv6)
		}
	}

	for _, service := range services {
		if len(ifaces) == 0 {
			wg.Add(1)
			go query(service, nil)
			continue
		}
		for _, iface := range ifaces {
			iface := iface
			wg.Add(1)
			go query(service, &iface)
		}
	}
	wg.Wait()

	if !ok {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// servicesFor returns the service types opts browses: opts.Services when it is
// not empty, each checked by validService, else ServiceTypes.
func servicesFor(opts Options) ([]string, error) {
	if len(opts.Services) == 0 {
		return ServiceTypes, nil
	}
	for _, s := range opts.Services {
		if !validService(s) {
			return nil, fmt.Errorf("%w %q: want _<name>._udp, the name 1 to 15 letters, digits, '-' or '_'", ErrBadService, s)
		}
	}
	return opts.Services, nil
}

// validService reports whether s is "_<name>._udp" (the suffix in any letter
// case), the name 1 to 15 letters, digits, '-' or '_': RFC 6335's length, with
// '_' because the sled types use it.
func validService(s string) bool {
	const suffix = "._udp"
	if len(s) < 1+len(suffix) || s[0] != '_' || !strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return false
	}
	name := s[1 : len(s)-len(suffix)]
	if len(name) < 1 || len(name) > 15 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// queryInterfaces returns the up, running, multicast-capable, non-loopback
// interfaces that have an IPv4 address, or with ipv6 any unicast IP address.
func queryInterfaces(ipv6 bool) []net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, i := range all {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagRunning == 0 ||
			i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, isNet := a.(*net.IPNet)
			if isNet && (n.IP.To4() != nil || ipv6 && (n.IP.IsGlobalUnicast() || n.IP.IsLinkLocalUnicast())) {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// collect merges one entry into out. hashicorp/mdns does not filter by
// service, so an entry whose name is not an instance of service is skipped.
// Without ipv6 an entry with no IPv4 address is skipped too. With ipv6 its
// IPv6 address is used instead; a link-local one needs the zone it was seen
// on (hashicorp/mdns takes it from the packet that carried the AAAA, so an
// answer over IPv4 leaves it empty) and is skipped without one. An entry with
// no usable address is skipped.
func collect(seen map[string]bool, out []Found, service string, e *mdns.ServiceEntry, ipv6 bool) []Found {
	suffix := "." + service + ".local."
	if !strings.HasSuffix(e.Name, suffix) {
		return out
	}
	instance := strings.TrimSuffix(e.Name, suffix)
	host := ""
	switch {
	case e.AddrV4 != nil:
		host = e.AddrV4.String()
	case ipv6 && e.AddrV6IPAddr != nil && e.AddrV6IPAddr.IP != nil:
		a := e.AddrV6IPAddr
		if a.IP.IsLinkLocalUnicast() && a.Zone == "" {
			return out
		}
		host = a.IP.String()
		if a.Zone != "" {
			host += "%" + a.Zone
		}
	default:
		return out
	}
	key := service + "/" + instance
	if seen[key] {
		return out
	}
	seen[key] = true
	f := Found{
		Instance: instance,
		Service:  service,
		Host:     host,
		Port:     e.Port,
		TXT:      map[string]string{},
	}
	for _, kv := range e.InfoFields {
		k, v, _ := strings.Cut(kv, "=")
		f.TXT[k] = v
	}
	if id, err := sledclient.DeviceIDFromInstance(instance); err == nil {
		f.DeviceID, f.HasDeviceID = id, true
	}
	return append(out, f)
}
