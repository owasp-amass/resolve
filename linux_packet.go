// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package resolve

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func (r *ConnPool) ListenPacket() (net.PacketConn, error) {
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
	if len(r.conns) > 0 {
		laddr = r.conns[0].conn.LocalAddr().String()
	}

	return lc.ListenPacket(context.Background(), "udp", laddr)
}
