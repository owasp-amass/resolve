// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
const DefaultTimeout = 100 * time.Millisecond

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

func (r *request) SendResponse(resp *dns.Msg) { r.deliver(resp) }

func (r *request) NoResponse() {
	r.Lock()
	resp := r.msg
	r.Unlock()

	resp.Rcode = RcodeNoResponse
	r.deliver(resp)
}

// deliver sends resp on the caller's response channel without ever crashing
// the process. The channel is owned by the caller, which may have stopped
// listening and closed it after a timeout, a cancellation, or an earlier
// answer; a late or duplicate response for a request nobody is waiting on is
// safe to drop. Every response channel in this module is buffered, so the
// non-blocking send still delivers the one expected answer and only skips a
// send that would otherwise block on a full buffer or panic on a closed one.
func (r *request) deliver(resp *dns.Msg) {
	defer func() { _ = recover() }()

	select {
	case r.resp <- resp:
	default:
	}
}

func (r *request) Release() {
	requestPool.Put(r)
}
