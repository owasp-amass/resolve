// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"errors"
	"net"
	"time"

	"github.com/owasp-amass/resolve/types"
)

func NewNameserver(addr string, timeout time.Duration) types.Nameserver {
	return newNameserver(addr, timeout)
}

func newNameserver(addr string, timeout time.Duration) *nameserver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	var ns *nameserver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		ns = &nameserver{
			done:    make(chan struct{}, 1),
			xchgs:   NewXchgMgr(timeout),
			addr:    uaddr,
			rate:    newRateTrack(),
			timeout: timeout,
		}
		go ns.timeouts()
	}
	return ns
}

func (ns *nameserver) Address() *net.UDPAddr {
	return ns.addr
}

func (ns *nameserver) XchgManager() types.XchgManager {
	return ns.xchgs
}

func (ns *nameserver) RateMonitor() types.RateTrack {
	return ns.rate
}

func (ns *nameserver) Close() {
	select {
	case <-ns.done:
		return
	default:
	}
	// Send the signal to shutdown and close the connection
	close(ns.done)
	// Drain the xchgs of all messages and allow callers to return
	for _, req := range ns.xchgs.RemoveAll() {
		req.NoResponse()
		req.Release()
	}
}

func (ns *nameserver) SendRequest(req types.Request, conns types.Conn) error {
	if req == nil {
		return errors.New("the request is nil")
	}

	select {
	case <-ns.done:
		req.NoResponse()
		req.Release()
		return errors.New("the nameserver has been closed")
	default:
	}

	ns.rate.Take()
	if err := ns.writeReq(req, conns); err != nil {
		req.NoResponse()
		req.Release()
		return err
	}
	return nil
}

func (ns *nameserver) writeReq(req types.Request, conns types.Conn) error {
	if conns == nil {
		return errors.New("the connection is nil")
	}

	if err := conns.WriteMsg(req, ns.addr); err != nil {
		return err
	}

	return ns.xchgs.Add(req)
}

func (ns *nameserver) timeouts() {
	t := time.NewTimer(ns.timeout)
	defer t.Stop()

	for range t.C {
		select {
		case <-ns.done:
			return
		default:
		}

		for _, req := range ns.xchgs.RemoveExpired() {
			req.NoResponse()
			req.Release()
		}

		t.Reset(ns.timeout)
	}
}
