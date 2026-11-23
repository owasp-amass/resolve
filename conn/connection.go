// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
)

const (
	headerSize      = 12
	expiredAt       = 5 * time.Second
	connectionDelay = 2 * time.Second
)

type connection struct {
	done      chan struct{}
	socks     []net.PacketConn
	bound     bool
	createdAt time.Time
	lookup    func(addr string) (types.Nameserver, error)
}

// newConnection opens one UDP socket on each local address, or one socket on
// every local address when there are none.
func newConnection(laddrs []netip.Addr, lookup func(addr string) (types.Nameserver, error)) *connection {
	c := &connection{
		done:      make(chan struct{}, 1),
		bound:     len(laddrs) > 0,
		createdAt: time.Now(),
		lookup:    lookup,
	}

	if !c.bound {
		laddrs = []netip.Addr{{}}
	}
	for _, laddr := range laddrs {
		pc, err := listen(laddr)
		if err != nil {
			for _, s := range c.socks {
				_ = s.Close()
			}
			return nil
		}

		_ = pc.SetDeadline(time.Time{})
		c.socks = append(c.socks, pc)
	}

	for _, pc := range c.socks {
		go c.responses(pc)
	}
	return c
}

// listen opens a UDP socket on the local address, or on every local address
// when it is the zero Addr.
func listen(laddr netip.Addr) (net.PacketConn, error) {
	if !laddr.IsValid() {
		return net.ListenPacket("udp", ":0")
	}

	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(laddr.Unmap(), 0)))
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// socket returns the socket that reaches the nameserver: the one bound to an
// address of its IP version, or the unbound socket.
func (c *connection) socket(dst *net.UDPAddr) (net.PacketConn, error) {
	if !c.bound {
		return c.socks[0], nil
	}

	v4 := dst.IP.To4() != nil
	for _, pc := range c.socks {
		if la, ok := pc.LocalAddr().(*net.UDPAddr); ok && (la.IP.To4() != nil) == v4 {
			return pc, nil
		}
	}

	version := 6
	if v4 {
		version = 4
	}
	return nil, fmt.Errorf("no local IPv%d address to reach the nameserver %s", version, dst)
}

func (c *connection) close() {
	select {
	case <-c.done:
	default:
		close(c.done)
		for _, pc := range c.socks {
			_ = pc.Close()
		}
	}
}

func delayedClose(c *connection) {
	time.Sleep(connectionDelay)
	c.close()
}

func (c *connection) expired() bool {
	return time.Since(c.createdAt) > expiredAt
}

func (c *connection) responses(pc net.PacketConn) {
	for {
		select {
		case <-c.done:
			return
		default:
		}
		c.handleSingleMessage(pc)
	}
}

func (c *connection) handleSingleMessage(pc net.PacketConn) {
	b := make([]byte, dns.DefaultMsgSize)

	_ = pc.SetReadDeadline(time.Now().Add(connectionDelay))
	if n, addr, err := pc.ReadFrom(b); err == nil && n >= headerSize {
		at := time.Now()

		m := new(dns.Msg)
		if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
			go c.processResponse(m, addr, at)
		}
	}
}

func (c *connection) processResponse(msg *dns.Msg, addr net.Addr, at time.Time) {
	a, _, _ := net.SplitHostPort(addr.String())

	if serv, err := c.lookup(a); err == nil {
		serv.RequestResponse(msg, at)
	}
}
