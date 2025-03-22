// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

const (
	headerSize = 12
	maxWrites  = 50
	maxJitter  = 10
)

type resp struct {
	Msg  *dns.Msg
	Addr net.Addr
	At   time.Time
}

type connection struct {
	done  chan struct{}
	conn  net.PacketConn
	count int
}

type Conn struct {
	done    chan struct{}
	conns   chan *connection
	expired chan *connection
	sel     types.Selector
	cpus    int
}

func New(cpus int, sel types.Selector) *Conn {
	conns := &Conn{
		done:    make(chan struct{}),
		conns:   make(chan *connection, cpus),
		expired: make(chan *connection, cpus),
		sel:     sel,
		cpus:    cpus,
	}

	for i := 0; i < cpus; i++ {
		conns.new()
	}

	go conns.rotations()
	return conns
}

func (r *Conn) Close() {
	close(r.done)
first:
	for i := 0; i < r.cpus; i++ {
		select {
		case c := <-r.conns:
			close(c.done)
			_ = c.conn.Close()
		default:
			break first
		}
	}
second:
	for i := 0; i < r.cpus; i++ {
		select {
		case c := <-r.expired:
			close(c.done)
			_ = c.conn.Close()
		default:
			break second
		}
	}

	close(r.conns)
	close(r.expired)
}

func (r *Conn) rotations() {
	for {
		select {
		case <-r.done:
			return
		case c := <-r.expired:
			r.new()
			go r.delayedClose(c)
		}
	}
}

func (r *Conn) delayedClose(c *connection) {
	time.Sleep(2 * time.Second)

	close(c.done)
	_ = c.conn.Close()
}

func (r *Conn) new() {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return
	}

	jitter := rand.Intn(maxJitter) + 1
	_ = conn.SetDeadline(time.Time{})
	c := &connection{
		done:  make(chan struct{}),
		conn:  conn,
		count: jitter,
	}
	go r.responses(c)

	r.conns <- c
}

func (r *Conn) WriteMsg(req types.Request, addr net.Addr) error {
	msg := req.Message().Copy()

	out, err := msg.Pack()
	if err != nil {
		return err
	}

	c := <-r.conns
	if c == nil {
		return errors.New("no available connections")
	}

	c.count++
	if c.count >= maxWrites {
		r.expired <- c
	} else {
		r.conns <- c
	}

	now := time.Now()
	req.SetSentAt(now)
	_ = c.conn.SetWriteDeadline(now.Add(2 * time.Second))

	n, err := c.conn.WriteTo(out, addr)
	if err == nil && n < len(out) {
		err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
	}
	return err
}

func (r *Conn) responses(c *connection) {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		if n, addr, err := c.conn.ReadFrom(b); err == nil && n >= headerSize {
			at := time.Now()

			m := new(dns.Msg)
			if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
				go r.processResponse(&resp{
					Msg:  m,
					Addr: addr,
					At:   at,
				})
			}
		}
	}
}

func (r *Conn) processResponse(response *resp) {
	addr, _, _ := net.SplitHostPort(response.Addr.String())

	serv := r.sel.Lookup(addr)
	if serv == nil {
		return
	}

	msg := response.Msg
	name := msg.Question[0].Name
	if req := serv.XchgManager().Remove(msg.Id, name); req != nil {
		req.SetResponse(msg)
		req.SetRecvAt(response.At)

		if req.Response().Truncated {
			utils.TCPExchange(req, 3*time.Second)
		} else {
			req.ResultChan() <- req.Response()
			rtt := req.RecvAt().Sub(req.SentAt())
			req.Server().RateMonitor().ReportRTT(rtt)
			req.Release()
		}
	}
}
