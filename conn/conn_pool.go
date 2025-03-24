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
)

type Conn struct {
	done  chan struct{}
	conns []*connection
	sel   types.Selector
	cpus  int
}

func New(cpus int, sel types.Selector) *Conn {
	conn := &Conn{
		done: make(chan struct{}),
		sel:  sel,
		cpus: cpus,
	}

	for i := 0; i < cpus; {
		if c := newConnection(sel.Lookup); c != nil {
			i++
			conn.conns = append(conn.conns, c)
		}
	}
	return conn
}

func (r *Conn) Close() {
	close(r.done)

	for _, c := range r.conns {
		c.close()
	}
}

func (r *Conn) getPacketConn() (net.PacketConn, error) {
	idx := rand.Intn(r.cpus)

	return r.conns[idx].get()
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

	c, err := r.getPacketConn()
	if err != nil {
		return err
	}

	err = ns.XchgManager().Modify(msg.Id, msg.Question[0].Name, func(req types.Request) {
		req.SetSentAt(time.Now())
	})
	if err != nil {
		return err
	}

	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, err := c.WriteTo(out, ns.Address())
	if err == nil && n < len(out) {
		err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
	}
	return err
}
