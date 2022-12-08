// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
)

const maxUDPBufferSize = 64 * 1024 * 1024

type resp struct {
	Msg  *dns.Msg
	Addr *net.UDPAddr
}

type connections struct {
	sync.Mutex
	done      chan struct{}
	conns     []*net.UDPConn
	resps     queue.Queue
	rbufSize  int
	wbufSize  int
	nextWrite int
}

func newConnections(cpus int, resps queue.Queue) *connections {
	conns := &connections{
		done:  make(chan struct{}, 1),
		resps: resps,
	}

	for i := 0; i < cpus; i++ {
		if err := conns.Add(); err != nil {
			conns.Close()
			return nil
		}
	}
	return conns
}

func (c *connections) Close() {
	select {
	case <-c.done:
		return
	default:
	}
	close(c.done)
	for _, conn := range c.conns {
		conn.Close()
	}
}

func (c *connections) Next() *net.UDPConn {
	c.Lock()
	defer c.Unlock()

	cur := c.nextWrite
	c.nextWrite = (c.nextWrite + 1) % len(c.conns)
	return c.conns[cur]
}

func (c *connections) Add() error {
	var err error
	var addr *net.UDPAddr
	var conn *net.UDPConn

	if addr, err = net.ResolveUDPAddr("udp", ":0"); err == nil {
		if conn, err = net.ListenUDP("udp", addr); err == nil {
			_ = conn.SetDeadline(time.Time{})
			c.setMaxReadBufSize(conn)
			c.setMaxWriteBufSize(conn)
			c.conns = append(c.conns, conn)
			go c.responses(conn)
		}
	}
	return err
}

func (c *connections) WriteMsg(msg *dns.Msg, addr *net.UDPAddr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		conn := c.Next()

		conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err = conn.WriteToUDP(out, addr); err == nil && n < len(out) {
			err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
		}
	}
	return err
}

func (c *connections) responses(conn *net.UDPConn) {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}
		if n, addr, err := conn.ReadFromUDP(b); err == nil && n >= headerSize {
			m := new(dns.Msg)

			if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
				c.resps.Append(&resp{
					Msg:  m,
					Addr: addr,
				})
			}
		}
	}
}

func (c *connections) setMaxReadBufSize(conn *net.UDPConn) {
	c.Lock()
	defer c.Unlock()

	if c.rbufSize != 0 {
		_ = conn.SetReadBuffer(c.rbufSize)
		return
	}

	min := 1024
	for size := maxUDPBufferSize; size > min; size /= 2 {
		if err := conn.SetReadBuffer(size); err == nil {
			c.rbufSize = size
			return
		}
	}
}

func (c *connections) setMaxWriteBufSize(conn *net.UDPConn) {
	c.Lock()
	defer c.Unlock()

	if c.wbufSize != 0 {
		_ = conn.SetWriteBuffer(c.wbufSize)
		return
	}

	min := 1024
	for size := maxUDPBufferSize; size > min; size /= 2 {
		if err := conn.SetWriteBuffer(size); err == nil {
			c.wbufSize = size
			return
		}
	}
}
