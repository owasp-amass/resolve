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

	"github.com/miekg/dns"
)

const headerSize = 12

type resp struct {
	Msg  *dns.Msg
	Addr net.Addr
	At   time.Time
}

type connection struct {
	conn net.PacketConn
	done chan struct{}
}

type ConnPool struct {
	sync.Mutex
	done      chan struct{}
	conns     []*connection
	sel       Selector
	nextWrite int
	cpus      int
}

func NewConnPool(cpus int, sel Selector) *ConnPool {
	conns := &ConnPool{
		done: make(chan struct{}),
		sel:  sel,
		cpus: cpus,
	}

	for i := 0; i < cpus; i++ {
		_ = conns.Add()
	}
	return conns
}

func (r *ConnPool) Close() {
	r.Lock()
	defer r.Unlock()

	if r.conns != nil {
		close(r.done)
		for _, c := range r.conns {
			close(c.done)
			_ = c.conn.Close()
		}
		r.conns = nil
	}
}

func (r *ConnPool) Next() net.PacketConn {
	r.Lock()
	defer r.Unlock()

	if len(r.conns) == 0 {
		return nil
	}

	cur := r.nextWrite
	r.nextWrite = (r.nextWrite + 1) % len(r.conns)
	return r.conns[cur].conn
}

func (r *ConnPool) Add() error {
	conn, err := r.ListenPacket()
	if err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Time{})
	c := &connection{
		conn: conn,
		done: make(chan struct{}),
	}
	go r.responses(c)

	r.conns = append(r.conns, c)
	return nil
}

func (r *ConnPool) WriteMsg(msg *dns.Msg, addr net.Addr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		err = errors.New("failed to obtain a connection")

		if conn := r.Next(); conn != nil {
			if n, err = conn.WriteTo(out, addr); err == nil && n < len(out) {
				err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
			}
		}
	}
	return err
}

func (r *ConnPool) responses(c *connection) {
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

func (r *ConnPool) processResponse(response *resp) {
	addr, _, _ := net.SplitHostPort(response.Addr.String())

	res := r.sel.LookupResolver(addr)
	if res == nil {
		return
	}

	msg := response.Msg
	name := msg.Question[0].Name
	if req := res.xchgs.remove(msg.Id, name); req != nil {
		req.Resp = msg
		req.RecvAt = response.At

		if req.Resp.Truncated {
			req.Res.tcpExchange(req)
		} else {
			req.Result <- req.Resp
			rtt := req.RecvAt.Sub(req.SentAt)
			req.Res.rate.ReportRTT(rtt)
			req.release()
		}
	}
}
