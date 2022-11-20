// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math/rand"
	"sync"
)

type selector interface {
	// GetResolver returns a resolver managed by the selector.
	GetResolver() *resolver

	// AddResolver adds a resolver to the selector pool.
	AddResolver(res *resolver)

	// AllResolvers returns all the resolver objects currently managed by the selector.
	AllResolvers() []*resolver

	// Len returns the number of resolver objects currently managed by the selector.
	Len() int

	// Close releases all resources allocated by the selector.
	Close()
}

type randomSelector struct {
	sync.Mutex
	list []*resolver
}

// GetResolver performs random selection on the pool of resolvers.
func (r *randomSelector) GetResolver() *resolver {
	var low int
	var chosen *resolver
loop:
	for _, res := range r.randList() {
		select {
		case <-res.done:
			continue loop
		default:
		}
		if cur := res.xchgQueue.Len(); chosen == nil || cur < low {
			chosen = res
			low = cur
		}
		if low == 0 {
			break
		}
	}
	return chosen
}

func (r *randomSelector) randList() []*resolver {
	r.Lock()
	defer r.Unlock()

	rlen := len(r.list)
	if rlen == 0 {
		return nil
	}

	slen := min(rlen, 25)
	var list []*resolver
	for a, i, j := 0, 0, rand.Intn(rlen); i < rlen && a < slen; i, j = i+1, (j+1)%rlen {
		select {
		case <-r.list[j].done:
		default:
			list = append(list, r.list[j])
			a++
		}
	}
	return list
}

func (r *randomSelector) AddResolver(res *resolver) {
	r.Lock()
	defer r.Unlock()

	r.list = append(r.list, res)
}

func (r *randomSelector) AllResolvers() []*resolver {
	r.Lock()
	defer r.Unlock()

	dst := make([]*resolver, len(r.list))
	copy(dst, r.list)
	return dst
}

// Len returns the number of resolvers that have been added to the pool.
func (r *randomSelector) Len() int {
	r.Lock()
	defer r.Unlock()

	return len(r.list)
}

func (r *randomSelector) Close() {
	r.Lock()
	defer r.Unlock()

	r.list = nil
}

func min(x, y int) int {
	m := x
	if y < m {
		m = y
	}
	return m
}
