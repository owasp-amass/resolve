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

func NewNameserver(addr string, timeout time.Duration) *nameserver {
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
	}

	go ns.timeouts()
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
		return errors.New("The request is nil")
	}

	select {
	case <-ns.done:
		req.NoResponse()
		req.Release()
		return errors.New("The nameserver has been closed")
	default:
	}

	ns.rate.Take()
	return ns.writeReq(req, conns)
}

func (ns *nameserver) writeReq(req types.Request, conns types.Conn) error {
	if conns == nil {
		req.NoResponse()
		req.Release()
		return errors.New("The connection is nil")
	}

	if err := ns.xchgs.Add(req); err != nil {
		req.NoResponse()
		req.Release()
		return err
	}

	msg := req.Message().Copy()
	req.SetSentAt(time.Now())
	if err := conns.WriteMsg(msg, ns.addr); err != nil {
		_ = ns.xchgs.Remove(msg.Id, msg.Question[0].Name)
		req.NoResponse()
		req.Release()
		return err
	}
	return nil
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
