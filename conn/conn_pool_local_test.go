// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/owasp-amass/resolve/types"
)

// noServers is a selector with no nameservers, for tests of the sockets alone.
type noServers struct{}

func (noServers) Get(string) (types.Nameserver, error)    { return nil, errors.New("no nameservers") }
func (noServers) Lookup(string) (types.Nameserver, error) { return nil, errors.New("no nameservers") }
func (noServers) All() []types.Nameserver                 { return nil }
func (noServers) Close()                                  {}

func TestNewLocalAddr(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")

	c := New(2, noServers{}, LocalAddr(netip.Addr{}, loopback, netip.MustParseAddr("127.0.0.2")))
	if c == nil {
		t.Fatal("New could not bind to the loopback address")
	}
	defer c.Close()

	for i := 0; i < 2; i++ {
		conn := c.get()
		if conn == nil {
			t.Fatal("the pool has fewer connections than it opened")
		}
		defer c.put(conn)

		// the zero Addr is ignored, and only the first IPv4 address is used
		if len(conn.socks) != 1 {
			t.Fatalf("the connection has %d sockets, want 1", len(conn.socks))
		}
		addr, ok := conn.socks[0].LocalAddr().(*net.UDPAddr)
		if !ok || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("the socket is bound to %v, want 127.0.0.1", conn.socks[0].LocalAddr())
		}

		if _, err := conn.socket(&net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}); err != nil {
			t.Errorf("no socket for an IPv4 nameserver: %v", err)
		}
		if _, err := conn.socket(&net.UDPAddr{IP: net.ParseIP("2001:db8::53"), Port: 53}); err == nil {
			t.Error("an IPv4-only connection offered a socket for an IPv6 nameserver")
		}
	}
}

func TestNewLocalAddrBothVersions(t *testing.T) {
	c := New(1, noServers{}, LocalAddr(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")))
	if c == nil {
		t.Skip("this host cannot bind to both 127.0.0.1 and ::1")
	}
	defer c.Close()

	conn := c.get()
	defer c.put(conn)

	for _, ip := range []string{"192.0.2.53", "2001:db8::53"} {
		pc, err := conn.socket(&net.UDPAddr{IP: net.ParseIP(ip), Port: 53})
		if err != nil {
			t.Errorf("no socket for %s: %v", ip, err)
			continue
		}

		la := pc.LocalAddr().(*net.UDPAddr)
		if (la.IP.To4() != nil) != (net.ParseIP(ip).To4() != nil) {
			t.Errorf("the socket for %s is bound to %v", ip, la)
		}
	}
}

func TestNewUnbound(t *testing.T) {
	c := New(1, noServers{})
	if c == nil {
		t.Fatal("New could not open an unbound socket")
	}
	defer c.Close()

	conn := c.get()
	defer c.put(conn)

	for _, ip := range []string{"192.0.2.53", "2001:db8::53"} {
		if _, err := conn.socket(&net.UDPAddr{IP: net.ParseIP(ip), Port: 53}); err != nil {
			t.Errorf("the unbound socket does not reach %s: %v", ip, err)
		}
	}
}

func TestNewLocalAddrNotOnHost(t *testing.T) {
	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	if c := New(2, noServers{}, LocalAddr(netip.MustParseAddr("192.0.2.1"))); c != nil {
		c.Close()
		t.Error("New bound to an address no interface has")
	}
}
