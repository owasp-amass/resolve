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

func NewXchgMgr(d time.Duration) *xchgMgr {
	return &xchgMgr{
		timeout: d,
		xchgs:   make(map[string]types.Request),
	}
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

func (r *xchgMgr) Remove(id uint16, name string) types.Request {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; found {
		return r.Delete([]string{key})[0]
	}
	return nil
}

func (r *xchgMgr) RemoveExpired() []types.Request {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	var keys []string
	for key, req := range r.xchgs {
		sent := req.SentAt()

		if !sent.IsZero() && now.After(sent.Add(r.timeout)) {
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
		removed = append(removed, r.xchgs[k])
		r.xchgs[k] = nil
		delete(r.xchgs, k)
	}
	return removed
}
