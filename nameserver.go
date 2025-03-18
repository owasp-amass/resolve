// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

type Nameserver struct {
	Address *net.UDPAddr
	done    chan struct{}
	xchgs   *xchgMgr
	rate    *rateTrack
}

func NewNameserver(addr string, timeout time.Duration) *Nameserver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	var ns *Nameserver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		ns = &Nameserver{
			done:    make(chan struct{}, 1),
			xchgs:   newXchgMgr(timeout),
			address: uaddr,
			rate:    newRateTrack(),
		}
	}
	return ns
}

func (ns *Nameserver) Stop() {
	select {
	case <-ns.done:
		return
	default:
	}
	// Send the signal to shutdown and close the connection
	close(ns.done)
	// Drain the xchgs of all messages and allow callers to return
	for _, req := range ns.xchgs.removeAll() {
		req.errNoResponse()
		req.release()
	}
}

func (ns *Nameserver) SendRequest(req *request, conns *ConnPool) {
	if req == nil {
		return
	}

	select {
	case <-ns.done:
		req.errNoResponse()
		req.release()
		return
	default:
	}

	ns.rate.Take()
	ns.writeReq(req, conns)
}

func (ns *Nameserver) writeReq(req *request, conns *ConnPool) {
	if conns == nil {
		req.errNoResponse()
		req.release()
		return
	}

	msg := req.Msg.Copy()
	req.SentAt = time.Now()

	if err := ns.xchgs.add(req); err != nil {
		req.errNoResponse()
		req.release()
	}

	if err := conns.WriteMsg(msg, ns.address); err != nil {
		_ = ns.xchgs.remove(msg.Id, msg.Question[0].Name)
		req.errNoResponse()
		req.release()
	}
}

func (ns *Nameserver) tcpExchange(req *request) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: 5 * time.Second,
	}

	if m, _, err := client.Exchange(req.Msg, ns.address.String()); err == nil {
		req.Result <- m
	} else {
		req.errNoResponse()
	}
	req.release()
}
