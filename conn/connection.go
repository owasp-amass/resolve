// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

const (
	headerSize = 12
	maxWrites  = 100
	maxJitter  = 10
	expiredAt  = 3 * time.Second
)

type connection struct {
	sync.Mutex
	done      chan struct{}
	conn      net.PacketConn
	count     int
	createdAt time.Time
	lookup    func(addr string) types.Nameserver
}

func newConnection(lookup func(addr string) types.Nameserver) *connection {
	conn := newPacketConn()
	if conn == nil {
		return nil
	}

	c := &connection{
		done:      make(chan struct{}),
		conn:      conn,
		count:     rand.Intn(maxJitter) + 1,
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

func (c *connection) get() net.PacketConn {
	c.Lock()
	defer c.Unlock()

	c.count++
	if c.expired() {
		go c.rotatePacketConn()
	}
	return c.conn
}

func (c *connection) rotatePacketConn() {
	pc := newPacketConn()
	if pc == nil {
		return
	}

	c.Lock()
	defer c.Unlock()

	o := c.conn
	c.conn = pc
	_ = o.Close()
	c.createdAt = time.Now()
	c.count = rand.Intn(maxJitter) + 1
}

func newPacketConn() net.PacketConn {
	var err error
	var success bool
	var pc net.PacketConn

	for i := 0; i < 10; i++ {
		pc, err = net.ListenPacket("udp", ":0")
		if err == nil {
			success = true
			break
		}

		backoff := utils.ExponentialBackoff(i+1, 100*time.Millisecond)
		time.Sleep(backoff)
	}
	if !success {
		return nil
	}

	_ = pc.SetDeadline(time.Time{})
	return pc
}

func (c *connection) expired() bool {
	return c.count >= maxWrites || time.Since(c.createdAt) > expiredAt
}

func (c *connection) responses() {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.Lock()
		pc := c.conn
		c.Unlock()

		if n, addr, err := pc.ReadFrom(b); err == nil && n >= headerSize {
			at := time.Now()

			m := new(dns.Msg)
			if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
				go c.processResponse(m, addr, at)
			}
		}
	}
}

func (c *connection) processResponse(msg *dns.Msg, addr net.Addr, at time.Time) {
	a, _, _ := net.SplitHostPort(addr.String())

	if serv := c.lookup(a); serv != nil {
		serv.RequestResponse(msg, at)
	}
}
