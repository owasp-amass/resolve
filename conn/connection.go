// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

const headerSize = 12

type connection struct {
	done   chan struct{}
	conn   net.PacketConn
	lookup func(addr string) types.Nameserver
}

func newConnection(lookup func(addr string) types.Nameserver) *connection {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil || conn == nil {
		return nil
	}

	_ = conn.SetDeadline(time.Time{})
	c := &connection{
		done:   make(chan struct{}),
		conn:   conn,
		lookup: lookup,
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

func (c *connection) responses() {
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
		} else {
			rtt := response.At.Sub(req.SentAt())
			req.Server().RateMonitor().ReportRTT(rtt)

			select {
			case req.RespChan() <- msg:
				req.Release()
			default:
			}
		}
	}
}
