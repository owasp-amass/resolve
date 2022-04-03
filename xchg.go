// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"fmt"
	"strings"
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
	r.Result <- r.Msg
}

func (r *request) release() {
	*r = request{} // Zero it out
	reqPool.Put(r)
}

// The xchgMgr handles DNS message IDs and identifying messages that have timed out.
type xchgMgr struct {
	sync.Mutex
	timeout time.Duration
	xchgs   map[string]*request
}

func newXchgMgr(d time.Duration) *xchgMgr {
	return &xchgMgr{
		timeout: d,
		xchgs:   make(map[string]*request),
	}
}

func xchgKey(id uint16, name string) string {
	return fmt.Sprintf("%d:%s", id, strings.ToLower(RemoveLastDot(name)))
}

func (r *xchgMgr) setTimeout(d time.Duration) {
	r.Lock()
	defer r.Unlock()

	r.timeout = d
}

func (r *xchgMgr) add(req *request) error {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(req.ID, req.Name)
	if _, found := r.xchgs[key]; found {
		return fmt.Errorf("key %s is already in use", key)
	}
	r.xchgs[key] = req
	return nil
}

func (r *xchgMgr) updateTimestamp(id uint16, name string) {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; !found {
		return
	}
	r.xchgs[key].Timestamp = time.Now()
}

func (r *xchgMgr) remove(id uint16, name string) *request {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; found {
		return r.delete([]string{key})[0]
	}
	return nil
}

func (r *xchgMgr) removeExpired() []*request {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	var keys []string
	for key, req := range r.xchgs {
		if !req.Timestamp.IsZero() && now.After(req.Timestamp.Add(r.timeout)) {
			keys = append(keys, key)
		}
	}
	return r.delete(keys)
}

func (r *xchgMgr) removeAll() []*request {
	r.Lock()
	defer r.Unlock()

	var keys []string
	for key := range r.xchgs {
		keys = append(keys, key)
	}
	return r.delete(keys)
}

func (r *xchgMgr) delete(keys []string) []*request {
	var removed []*request

	for _, k := range keys {
		removed = append(removed, r.xchgs[k])
		r.xchgs[k] = nil
		delete(r.xchgs, k)
	}
	return removed
}
