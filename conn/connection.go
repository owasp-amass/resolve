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
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil || conn == nil {
		return nil
	}

	_ = conn.SetDeadline(time.Time{})
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
		c.rotatePacketConn()
	}
	return c.conn
}

func (c *connection) rotatePacketConn() {
	pc := c.newPacketConn()
	if pc == nil {
		return
	}

	o := c.conn
	c.conn = pc
	_ = o.Close()
	c.createdAt = time.Now()
	c.count = rand.Intn(maxJitter) + 1
}

func (c *connection) newPacketConn() net.PacketConn {
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
				go c.processResponse(&resp{
					Msg:  m,
					Addr: addr,
					At:   at,
				})
			}
		}
	}
}

type resp struct {
	Msg  *dns.Msg
	Addr net.Addr
	At   time.Time
}

func (c *connection) processResponse(response *resp) {
	addr, _, _ := net.SplitHostPort(response.Addr.String())

	serv := c.lookup(addr)
	if serv == nil {
		return
	}

	msg := response.Msg
	name := msg.Question[0].Name

	if req := serv.XchgManager().Remove(msg.Id, name); req != nil {
		if msg.Truncated {
			utils.TCPExchange(req, 3*time.Second)
			return
		}

		rtt := response.At.Sub(req.SentAt())
		req.Server().RateMonitor().ReportRTT(rtt)

		select {
		case req.RespChan() <- msg:
			req.Release()
		default:
		}
	}
}
