// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"sync"
	"time"

	"gihub.com/oswp-amass/resolve/types"
	"github.com/miekg/dns"
)

// RcodeNoResponse is a special status code used to indicate no response or package error.
const RcodeNoResponse int = 50

// DefaultTimeout is the duration waited until a DNS query expires.
const DefaultTimeout = 2 * time.Second

var RequestPool = sync.Pool{
	New: func() interface{} {
		return new(request)
	},
}

func (r *request) Server() types.Nameserver      { return r.serv }
func (r *request) SetServer(s *types.Nameserver) { r.serv = s }
func (r *request) SentAt() time.Time             { return r.sentAt }
func (r *request) SetSentAt(t time.Time)         { r.sentAt = t }
func (r *request) RecvAt() time.Time             { return r.recvAt }
func (r *request) SetRecvAt(t time.Time)         { r.recvAt = t }
func (r *request) Message() *dns.Msg             { return r.msg }
func (r *request) SetMessage(m *dns.Msg)         { r.msg = m }
func (r *request) Response() *dns.Msg            { return r.resp }
func (r *request) SetResponse(m *dns.Msg)        { r.resp = m }
func (r *request) ResultChan() chan *dns.Msg     { return r.result }
func (r *request) SetResultChan(c chan *dns.Msg) { r.result = c }

func (r *request) NoResponse() {
	if r.msg != nil {
		r.msg.Rcode = RcodeNoResponse
	}
	r.result <- r.msg
}

func (r *request) Release() {
	*r = request{} // Zero it out
	RequestPool.Put(r)
}
