// Copyright © by Jeff Foley 2022-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const headerSize = 12

type resp struct {
	Msg  *dns.Msg
	Addr net.Addr
}

type connections struct {
	sync.Mutex
	done      chan struct{}
	conns     []net.PacketConn
	resps     queue.Queue
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

func (c *connections) Next() net.PacketConn {
	c.Lock()
	defer c.Unlock()

	cur := c.nextWrite
	c.nextWrite = (c.nextWrite + 1) % len(c.conns)
	return c.conns[cur]
}

func (c *connections) Add() error {
	var err error
	var conn net.PacketConn

	if runtime.GOOS == "linux" {
		conn, err = c.linuxListenPacket()
	} else {
		conn, err = net.ListenPacket("udp", ":0")
	}

	if err == nil {
		_ = conn.SetDeadline(time.Time{})
		c.conns = append(c.conns, conn)
		go c.responses(conn)
	}
	return err
}

func (c *connections) linuxListenPacket() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error

			if err := c.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}

			return operr
		},
	}

	laddr := ":0"
	if len(c.conns) > 0 {
		laddr = c.conns[0].LocalAddr().String()
	}

	return lc.ListenPacket(context.Background(), "udp", laddr)
}

func (c *connections) WriteMsg(msg *dns.Msg, addr net.Addr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		conn := c.Next()

		_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err = conn.WriteTo(out, addr); err == nil && n < len(out) {
			err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
		}
	}
	return err
}

func (c *connections) responses(conn net.PacketConn) {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}
		if n, addr, err := conn.ReadFrom(b); err == nil && n >= headerSize {
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
