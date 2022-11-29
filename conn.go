// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
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

	var failed bool
	for i := 0; i < cpus; i++ {
		if err := conns.Add(); err != nil {
			failed = true
			break
		}
	}

	if failed {
		conns.Close()
		return nil
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
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return err
	}

	c.setMaxReadBufSize(conn)
	c.setMaxWriteBufSize(conn)
	c.conns = append(c.conns, conn)
	go c.responses(conn)
	return nil
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
