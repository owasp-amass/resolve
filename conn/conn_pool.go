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

	"github.com/owasp-amass/resolve/types"
)

const maxJitter = 10

type Conn struct {
	done  chan struct{}
	conns chan *connection
	sel   types.Selector
	cpus  int
}

func New(cpus int, sel types.Selector) *Conn {
	conns := &Conn{
		done:  make(chan struct{}),
		conns: make(chan *connection, cpus),
		sel:   sel,
		cpus:  cpus,
	}

	for i := 0; i < cpus; {
		if c := conns.new(); c != nil {
			i++
			conns.putConnection(c)
		}
	}
	return conns
}

func (r *Conn) Close() {
	close(r.done)
	defer close(r.conns)
loop:
	for i := 0; i < r.cpus; i++ {
		select {
		case c := <-r.conns:
			c.close()
		default:
			break loop
		}
	}
}

func (r *Conn) new() *connection {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil || conn == nil {
		return nil
	}

	jitter := rand.Intn(maxJitter) + 1
	_ = conn.SetDeadline(time.Time{})
	c := &connection{
		done:      make(chan struct{}),
		conn:      conn,
		count:     jitter,
		createdAt: time.Now(),
		lookup:    r.sel.Lookup,
	}

	go c.responses()
	return c
}

func (r *Conn) getConnection() *connection {
	var c *connection
	t := time.NewTimer(time.Second)
	defer t.Stop()

	select {
	case <-r.done:
		return nil
	case <-t.C:
		c = r.new()
	case c = <-r.conns:
		c.count++
		if c.expired() {
			go c.delayedClose()
			c = r.new()
		}
	}

	if c != nil {
		r.putConnection(c)
	}
	return c
}

func (r *Conn) putConnection(c *connection) {
	select {
	case r.conns <- c:
	default:
		go c.delayedClose()
	}
}

func (r *Conn) WriteMsg(req types.Request, addr net.Addr) error {
	select {
	case <-r.done:
		return errors.New("the connection pool has been closed")
	default:
	}
	msg := req.Message().Copy()

	out, err := msg.Pack()
	if err != nil {
		return err
	}

	c := r.getConnection()
	if c == nil {
		return errors.New("failed to obtain a connection")
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
