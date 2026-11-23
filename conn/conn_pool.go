// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
)

// socketAttempts is how many times New tries to open each socket.
const socketAttempts = 3

type Conn struct {
	done  chan struct{}
	conns chan *connection
	sel   types.Selector
	laddr netip.Addr
	cpus  int
}

// Option configures the connections New returns.
type Option func(*Conn)

// LocalAddr binds the UDP sockets to the local address, so the queries leave
// through the network interface that has it. The zero Addr leaves the choice
// to the system.
func LocalAddr(addr netip.Addr) Option {
	return func(c *Conn) {
		c.laddr = addr
	}
}

// New opens cpus UDP sockets that send queries to the selector's nameservers
// and pass their responses back. It returns nil when the sockets cannot be
// opened, such as when the local address is not on any network interface.
func New(cpus int, sel types.Selector, opts ...Option) *Conn {
	conn := &Conn{
		done:  make(chan struct{}),
		conns: make(chan *connection, cpus),
		sel:   sel,
		cpus:  cpus,
	}
	for _, opt := range opts {
		opt(conn)
	}

	for i := 0; i < cpus; i++ {
		var c *connection
		for a := 0; a < socketAttempts && c == nil; a++ {
			c = newConnection(conn.laddr, sel.Lookup)
		}

		if c == nil {
			for ; i > 0; i-- {
				(<-conn.conns).close()
			}
			return nil
		}
		conn.conns <- c
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
	t := time.NewTimer(time.Second)
	defer t.Stop()

	select {
	case c := <-r.conns:
		if c != nil {
			return c
		}
	case <-t.C:
	}
	return nil
}

// put returns the connection to the pool, replacing it when it has expired.
// When a new socket cannot be opened, the old one stays in use, so the pool
// keeps all its connections and Close finds every one.
func (r *Conn) put(c *connection) {
	if c.expired() {
		if nc := newConnection(r.laddr, r.sel.Lookup); nc != nil {
			go delayedClose(c)
			c = nc
		}
	}
	r.conns <- c
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
	if c == nil {
		return errors.New("failed to obtain a connection")
	}
	defer r.put(c)

	if err := ns.XchgManager().Modify(msg.Id, msg.Question[0].Name, func(req types.Request) {
		req.SetSentAt(time.Now())
	}); err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}

	n, err := c.conn.WriteTo(out, ns.Address())
	if err == nil && n < len(out) {
		err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
	}
	return err
}
