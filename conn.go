// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
)

const headerSize = 12

type resp struct {
	Msg  *dns.Msg
	Addr net.Addr
}

type connection struct {
	conn net.PacketConn
	done chan struct{}
}

type connections struct {
	sync.Mutex
	done      chan struct{}
	conns     []*connection
	resps     queue.Queue
	nextWrite int
	cpus      int
}

func newConnections(cpus int, resps queue.Queue) *connections {
	if cpus < 100 {
		cpus = 100
	}

	conns := &connections{
		resps: resps,
		done:  make(chan struct{}),
		cpus:  cpus,
	}

	conns.Lock()
	defer conns.Unlock()

	for i := 0; i < cpus; i++ {
		if err := conns.Add(); err != nil {
			conns.Close()
			return nil
		}
	}
	go conns.rotations()
	return conns
}

func (r *connections) Close() {
	r.Lock()
	defer r.Unlock()

	if r.conns != nil {
		close(r.done)
		for _, c := range r.conns {
			close(c.done)
		}
		r.conns = nil
	}
}

func (r *connections) rotations() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.rotate()
		}
	}
}

func (r *connections) rotate() {
	r.Lock()
	defer r.Unlock()

	for _, c := range r.conns {
		go func(c *connection) {
			t := time.NewTimer(10 * time.Second)
			defer t.Stop()

			<-t.C
			close(c.done)
		}(c)
	}

	r.conns = []*connection{}
	for i := 0; i < r.cpus; i++ {
		_ = r.Add()
	}
}

func (r *connections) Next() net.PacketConn {
	r.Lock()
	defer r.Unlock()

	if len(r.conns) == 0 {
		return nil
	}

	cur := r.nextWrite
	r.nextWrite = (r.nextWrite + 1) % len(r.conns)
	return r.conns[cur].conn
}

func (r *connections) Add() error {
	conn, err := r.ListenPacket()
	if err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Time{})
	c := &connection{
		conn: conn,
		done: make(chan struct{}),
	}
	r.conns = append(r.conns, c)
	go r.responses(c)
	return nil
}

func (r *connections) WriteMsg(msg *dns.Msg, addr net.Addr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		err = errors.New("failed to obtain a connection")

		if conn := r.Next(); conn != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))

			n, err = conn.WriteTo(out, addr)
			if err == nil && n < len(out) {
				err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
			}
		}
	}
	return err
}

func (r *connections) responses(c *connection) {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			_ = c.conn.Close()
			return
		default:
		}
		if n, addr, err := c.conn.ReadFrom(b); err == nil && n >= headerSize {
			m := new(dns.Msg)

			if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
				r.resps.Append(&resp{
					Msg:  m,
					Addr: addr,
				})
			}
		}
	}
}
