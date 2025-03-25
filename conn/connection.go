// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"net"
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
	conn      net.PacketConn
	createdAt time.Time
	lookup    func(addr string) (types.Nameserver, error)
}

func newConnection(lookup func(addr string) (types.Nameserver, error)) *connection {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil
	}
	_ = pc.SetDeadline(time.Time{})

	c := &connection{
		done:      make(chan struct{}, 1),
		conn:      pc,
		createdAt: time.Now(),
		lookup:    lookup,
	}

	go c.responses()
	return c
}

func (c *connection) close() {
	select {
	case <-c.done:
	default:
		close(c.done)
		_ = c.conn.Close()
	}
}

func delayedClose(c *connection) {
	time.Sleep(connectionDelay)
	c.close()
}

func (c *connection) expired() bool {
	return time.Since(c.createdAt) > expiredAt
}

func (c *connection) responses() {
	for {
		select {
		case <-c.done:
			return
		default:
		}
		c.handleSingleMessage(c.conn)
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
