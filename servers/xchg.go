// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

func NewXchgMgr() *xchgMgr {
	return &xchgMgr{xchgs: make(map[string]types.Request)}
}

func xchgKey(id uint16, name string) string {
	return fmt.Sprintf("%d:%s", id, strings.ToLower(utils.RemoveLastDot(name)))
}

func (r *xchgMgr) Add(req types.Request) error {
	r.Lock()
	defer r.Unlock()

	msg := req.Message()
	key := xchgKey(msg.Id, msg.Question[0].Name)
	if _, found := r.xchgs[key]; found {
		return fmt.Errorf("key %s is already in use", key)
	}
	r.xchgs[key] = req
	return nil
}

func (r *xchgMgr) Remove(id uint16, name string) (types.Request, bool) {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; found {
		if reqs := r.Delete([]string{key}); len(reqs) > 0 {
			return reqs[0], true
		}
	}
	return nil, false
}

func (r *xchgMgr) RemoveExpired(timeout time.Duration) []types.Request {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	var keys []string
	for key, req := range r.xchgs {
		if sent := req.SentAt(); !sent.IsZero() && now.After(sent.Add(timeout)) {
			keys = append(keys, key)
		}
	}

	return r.Delete(keys)
}

func (r *xchgMgr) RemoveAll() []types.Request {
	r.Lock()
	defer r.Unlock()

	var keys []string
	for key := range r.xchgs {
		keys = append(keys, key)
	}

	return r.Delete(keys)
}

func (r *xchgMgr) Delete(keys []string) []types.Request {
	var removed []types.Request

	for _, k := range keys {
		if req, found := r.xchgs[k]; found {
			removed = append(removed, req)
			r.xchgs[k] = nil
			delete(r.xchgs, k)
		}
	}
	return removed
}
