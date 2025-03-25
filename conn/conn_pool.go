// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
)

type Conn struct {
	done  chan struct{}
	conns chan *connection
	sel   types.Selector
	cpus  int
}

func New(cpus int, sel types.Selector) *Conn {
	conn := &Conn{
		done:  make(chan struct{}),
		conns: make(chan *connection, cpus),
		sel:   sel,
		cpus:  cpus,
	}

	for i := 0; i < cpus; {
		if c := newConnection(sel.Lookup); c != nil {
			i++
			conn.conns <- c
		}
	}
	return conn
}

func (r *Conn) Close() {
	close(r.done)

	for i := 0; i < r.cpus; i++ {
		c := <-r.conns
		c.close()
	}
}

func (r *Conn) get() *connection {
	c := <-r.conns

	c.count++
	return c
}

func (r *Conn) put(c *connection) {
	n := c

	if c.expired() {
		go c.delayedClose()
		n = newConnection(r.sel.Lookup)
	}

	r.conns <- n
}

func (r *Conn) WriteMsg(msg *dns.Msg, ns types.Nameserver) error {
	select {
	case <-r.done:
		return errors.New("the connection pool has been closed")
	default:
	}

	out, err := msg.Pack()
	if err != nil {
		return err
	}

	c := r.get()
	defer r.put(c)

	err = ns.XchgManager().Modify(msg.Id, msg.Question[0].Name, func(req types.Request) {
		req.SetSentAt(time.Now())
	})
	if err != nil {
		return err
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, err := c.conn.WriteTo(out, ns.Address())
	if err == nil && n < len(out) {
		err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
	}
	return err
}
