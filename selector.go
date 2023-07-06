// Copyright © by Jeff Foley 2022-2023. All rights reserved.
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

	// LookupResolver returns the resolver with the matching address.
	LookupResolver(addr string) *resolver

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
	list   []*resolver
	lookup map[string]*resolver
}

func newRandomSelector() *randomSelector {
	return &randomSelector{lookup: make(map[string]*resolver)}
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
		if cur := res.xchgs.len(); chosen == nil || cur < low {
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

func (r *randomSelector) LookupResolver(addr string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *randomSelector) AddResolver(res *resolver) {
	r.Lock()
	defer r.Unlock()

	if _, found := r.lookup[res.address.IP.String()]; !found {
		r.list = append(r.list, res)
		r.lookup[res.address.IP.String()] = res
	}
}

func (r *randomSelector) AllResolvers() []*resolver {
	r.Lock()
	defer r.Unlock()

	var active []*resolver
	for _, res := range r.list {
		select {
		case <-res.done:
		default:
			active = append(active, res)
		}
	}
	return active
}

func (r *randomSelector) Len() int {
	r.Lock()
	defer r.Unlock()

	var count int
	for _, res := range r.list {
		select {
		case <-res.done:
		default:
			count++
		}
	}
	return count
}

func (r *randomSelector) Close() {
	r.Lock()
	defer r.Unlock()

	r.list = nil
	r.lookup = nil
}

func min(x, y int) int {
	m := x
	if y < m {
		m = y
	}
	return m
}
