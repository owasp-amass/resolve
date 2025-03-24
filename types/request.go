// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RcodeNoResponse is a special status code used to indicate no response or package error.
const RcodeNoResponse int = 50

// DefaultTimeout is the duration waited until a DNS query expires.
const DefaultTimeout = 2 * time.Second

type Request interface {
	Server() Nameserver
	SetServer(s Nameserver)
	SentAt() time.Time
	SetSentAt(t time.Time)
	Message() *dns.Msg
	SetMessage(m *dns.Msg)
	SetRespChan(c chan *dns.Msg)
	SendResponse(resp *dns.Msg)
	NoResponse()
	Release()
}

var RequestPool = sync.Pool{
	New: func() any {
		return new(request)
	},
}

type request struct {
	sync.Mutex
	serv   Nameserver
	sentAt time.Time
	msg    *dns.Msg
	resp   chan *dns.Msg
}

func (r *request) Server() Nameserver {
	r.Lock()
	defer r.Unlock()

	return r.serv
}

func (r *request) SetServer(s Nameserver) {
	r.Lock()
	defer r.Unlock()

	r.serv = s
}

func (r *request) SentAt() time.Time {
	r.Lock()
	defer r.Unlock()

	return r.sentAt
}

func (r *request) SetSentAt(t time.Time) {
	r.Lock()
	defer r.Unlock()

	r.sentAt = t
}

func (r *request) Message() *dns.Msg {
	r.Lock()
	defer r.Unlock()

	return r.msg
}

func (r *request) SetMessage(m *dns.Msg) {
	r.Lock()
	defer r.Unlock()

	r.msg = m
}

func (r *request) SetRespChan(c chan *dns.Msg) {
	r.Lock()
	defer r.Unlock()

	r.resp = c
}

func (r *request) SendResponse(resp *dns.Msg) { r.resp <- resp }

func (r *request) NoResponse() {
	r.Lock()
	defer r.Unlock()

	r.msg.Rcode = RcodeNoResponse
	r.resp <- r.msg
}

func (r *request) Release() {
	*r = request{} // Zero it out
	RequestPool.Put(r)
}
