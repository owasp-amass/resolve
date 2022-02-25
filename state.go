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

// QueryTimeout is the duration until a Resolver query expires.
var QueryTimeout = 2 * time.Second

type resolveRequest struct {
	Ctx       context.Context
	ID        uint16
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Msg       *dns.Msg
	Result    chan *dns.Msg
}

type xchgManager struct {
	sync.Mutex
	xchgs map[string]*resolveRequest
}

func newXchgManager() *xchgManager {
	return &xchgManager{xchgs: make(map[string]*resolveRequest)}
}

func xchgKey(id uint16, name string) string {
	return fmt.Sprintf("%d:%s", id, strings.ToLower(RemoveLastDot(name)))
}

func (r *xchgManager) add(req *resolveRequest) error {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(req.ID, req.Name)
	if _, found := r.xchgs[key]; found {
		return fmt.Errorf("key %s is already in use", key)
	}

	r.xchgs[key] = req
	return nil
}

func (r *xchgManager) updateTimestamp(id uint16, name string) {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; !found {
		return
	}

	r.xchgs[key].Timestamp = time.Now()
}

func (r *xchgManager) remove(id uint16, name string) *resolveRequest {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; !found {
		return nil
	}

	reqs := r.delete([]string{key})
	if len(reqs) != 1 {
		return nil
	}

	return reqs[0]
}

func (r *xchgManager) removeExpired() []*resolveRequest {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	var keys []string
	for key, req := range r.xchgs {
		if !req.Timestamp.IsZero() && now.After(req.Timestamp.Add(QueryTimeout)) {
			keys = append(keys, key)
		}
	}

	return r.delete(keys)
}

func (r *xchgManager) removeAll() []*resolveRequest {
	r.Lock()
	defer r.Unlock()

	var keys []string
	for key := range r.xchgs {
		keys = append(keys, key)
	}

	return r.delete(keys)
}

func (r *xchgManager) delete(keys []string) []*resolveRequest {
	var removed []*resolveRequest

	for _, k := range keys {
		removed = append(removed, r.xchgs[k])
		r.xchgs[k] = nil
		delete(r.xchgs, k)
	}

	return removed
}
