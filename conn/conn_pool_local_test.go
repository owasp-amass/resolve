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

	c := New(2, noServers{}, LocalAddr(loopback))
	if c == nil {
		t.Fatal("New could not bind to the loopback address")
	}
	defer c.Close()

	for i := 0; i < 2; i++ {
		conn := c.get()
		if conn == nil {
			t.Fatal("the pool has fewer connections than it opened")
		}

		addr, ok := conn.conn.LocalAddr().(*net.UDPAddr)
		if !ok || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("the socket is bound to %v, want 127.0.0.1", conn.conn.LocalAddr())
		}
		defer c.put(conn)
	}
}

func TestNewLocalAddrNotOnHost(t *testing.T) {
	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	if c := New(2, noServers{}, LocalAddr(netip.MustParseAddr("192.0.2.1"))); c != nil {
		c.Close()
		t.Error("New bound to an address no interface has")
	}
}
