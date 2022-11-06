// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RcodeNoResponse is a special status code used to indicate no response or package error.
const RcodeNoResponse int = 50

// DefaultTimeout is the duration waited until a DNS query expires.
const DefaultTimeout = time.Second

var reqPool = sync.Pool{
	New: func() interface{} {
		return new(request)
	},
}

type request struct {
	Ctx       context.Context
	ID        uint16
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Msg       *dns.Msg
	Result    chan *dns.Msg
}

func (r *request) errNoResponse() {
	if r.Msg != nil {
		r.Msg.Rcode = RcodeNoResponse
	}

	select {
	case r.Result <- r.Msg:
	default:
		go func(ch chan *dns.Msg) { ch <- r.Msg }(r.Result)
	}
}

func (r *request) release() {
	*r = request{} // Zero it out
	reqPool.Put(r)
}

type resolver struct {
	address string
	last    time.Time
	rate    time.Duration
	timeout time.Duration
}

func initializeResolver(addr string, timeout time.Duration) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	return &resolver{
		address: addr,
		last:    time.Now(),
		rate:    10 * time.Millisecond,
		timeout: timeout,
	}
}

func (r *resolver) exchange(req *request) {
	m, rtt, err := r.xchg(req, "udp")
	if err == nil && m.Truncated {
		m, rtt, err = r.xchg(req, "tcp")
	}
	if err != nil {
		req.errNoResponse()
		req.release()
		return
	}
	r.rate = rtt

	select {
	case req.Result <- m:
	default:
		go func(ch chan *dns.Msg) { ch <- m }(req.Result)
	}
	req.release()
}

func (r *resolver) xchg(req *request, protocol string) (*dns.Msg, time.Duration, error) {
	client := dns.Client{
		Net:     protocol,
		Timeout: r.timeout,
	}

	if protocol == "tcp" {
		client.Timeout = time.Minute
	} else {
		client.UDPSize = dns.DefaultMsgSize
	}

	r.last = time.Now()
	return client.ExchangeContext(req.Ctx, req.Msg, r.address)
}
