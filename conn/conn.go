// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

const (
	headerSize = 12
	maxWrites  = 50
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
	sync.Mutex
	done      chan struct{}
	conns     []*connection
	sel       types.Selector
	nextWrite int
}

func New(cpus int, sel types.Selector) *Conn {
	conns := &Conn{
		done: make(chan struct{}),
		sel:  sel,
	}

	for i := 0; i < cpus; i++ {
		_ = conns.add()
	}
	return conns
}

func (r *Conn) Close() {
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

func (r *Conn) next() net.PacketConn {
	r.Lock()
	defer r.Unlock()

	if len(r.conns) == 0 {
		return nil
	}

	cur := r.nextWrite
	r.nextWrite = (r.nextWrite + 1) % len(r.conns)

	r.conns[cur].count++
	if r.conns[cur].count >= maxWrites {
		r.conns = append(r.conns[:cur], r.conns[cur+1:]...)
		go r.delayedClose(r.conns[cur])
	}

	return r.conns[cur].conn
}

func (r *Conn) delayedClose(c *connection) {
	_ = r.add()
	time.Sleep(2 * time.Second)

	close(c.done)
	_ = c.conn.Close()
}

func (r *Conn) add() error {
	r.Lock()
	defer r.Unlock()

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

func (r *Conn) WriteMsg(msg *dns.Msg, addr net.Addr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		err = errors.New("failed to obtain a connection")

		if conn := r.next(); conn != nil {
			if n, err = conn.WriteTo(out, addr); err == nil && n < len(out) {
				err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
			}
		}
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
			utils.TCPExchange(req, 2*time.Second)
		} else {
			req.ResultChan() <- req.Response()
			rtt := req.RecvAt().Sub(req.SentAt())
			req.Server().RateMonitor().ReportRTT(rtt)
			req.Release()
		}
	}
}
