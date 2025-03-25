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
	SendResponse(resp *dns.Msg)
	NoResponse()
	Release()
}

type request struct {
	sync.Mutex
	serv   Nameserver
	sentAt time.Time
	msg    *dns.Msg
	resp   chan *dns.Msg
}

var requestPool = sync.Pool{
	New: func() any {
		return new(request)
	},
}

func NewRequest(msg *dns.Msg, ch chan *dns.Msg) Request {
	r := requestPool.Get().(*request)

	r.msg = msg
	r.resp = ch
	r.sentAt = time.Time{}
	return r
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

func (r *request) SendResponse(resp *dns.Msg) { r.resp <- resp }

func (r *request) NoResponse() {
	r.Lock()
	resp := r.msg
	r.Unlock()

	resp.Rcode = RcodeNoResponse
	r.resp <- resp
}

func (r *request) Release() {
	requestPool.Put(r)
}
