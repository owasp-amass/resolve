// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
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
	pc, err := newPacketConn()
	if err != nil {
		return nil
	}

	c := &connection{
		done:      make(chan struct{}),
		conn:      pc,
		count:     rand.Intn(maxJitter) + 1,
		createdAt: time.Now(),
		lookup:    lookup,
	}

	go c.responses()
	return c
}

func (c *connection) close() {
	c.Lock()
	defer c.Unlock()

	select {
	case <-c.done:
	default:
		close(c.done)
		_ = c.conn.Close()
	}
}

func (c *connection) get() (net.PacketConn, error) {
	select {
	case <-c.done:
		return nil, errors.New("the connection has been closed")
	default:
	}

	c.Lock()
	defer c.Unlock()

	c.count++
	if c.expired() {
		c.createdAt = time.Now()
		c.count = rand.Intn(maxJitter) + 1
	}
	return c.conn, nil
}

func newPacketConn() (net.PacketConn, error) {
	var err error
	var success bool
	var pc net.PacketConn

	for i := 0; i < 10; i++ {
		pc, err = net.ListenPacket("udp", ":0")
		if err == nil {
			success = true
			break
		}

		backoff := utils.ExponentialBackoff(i, 250*time.Millisecond)
		time.Sleep(backoff)
	}
	if !success {
		return nil, err
	}

	_ = pc.SetDeadline(time.Time{})
	return pc, nil
}

func (c *connection) expired() bool {
	return c.count >= maxWrites || time.Since(c.createdAt) > expiredAt
}

func (c *connection) responses() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.Lock()
		pc := c.conn
		c.Unlock()

		c.handleSingleMessage(pc)
	}
}

func (c *connection) handleSingleMessage(pc net.PacketConn) {
	b := make([]byte, dns.DefaultMsgSize)

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

	if serv := c.lookup(a); serv != nil {
		serv.RequestResponse(msg, at)
	}
}
