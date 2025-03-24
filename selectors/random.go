// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"math/rand"
	"time"

	"github.com/owasp-amass/resolve/types"
)

func NewRandom(timeout time.Duration) *random {
	r := &random{
		done:    make(chan struct{}, 1),
		timeout: timeout,
		lookup:  make(map[string]types.Nameserver),
	}

	go r.timeouts()
	return r
}

// Get performs random selection on the pool of nameservers.
func (r *random) Get(fqdn string) types.Nameserver {
	r.Lock()
	defer r.Unlock()

	if l := len(r.list); l == 0 {
		return nil
	} else if l == 1 {
		return r.list[0]
	}

	sel := rand.Intn(len(r.list))
	return r.list[sel]
}

func (r *random) Lookup(addr string) types.Nameserver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *random) Add(ns types.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address().IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, ns)
		r.lookup[addrstr] = ns
	}
}

func (r *random) Remove(ns types.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address().IP.String()
	if _, found := r.lookup[addrstr]; found {
		delete(r.lookup, addrstr)

		for i, n := range r.list {
			if n == ns {
				r.list = append(r.list[:i], r.list[i+1:]...)
				break
			}
		}
	}
}

func (r *random) All() []types.Nameserver {
	r.Lock()
	defer r.Unlock()

	all := make([]types.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	return all
}

func (r *random) Close() {
	close(r.done)

	r.Lock()
	all := make([]types.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	r.Unlock()

	for _, ns := range all {
		r.Remove(ns)
		ns.Close()
	}

	r.list = nil
	r.lookup = nil
}

func (r *random) timeouts() {
	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}

		r.Lock()
		cp := make([]types.Nameserver, 0, len(r.list))
		_ = copy(cp, r.list)
		r.Unlock()

		for _, ns := range cp {
			for _, req := range ns.XchgManager().RemoveExpired(r.timeout) {
				req.NoResponse()
				req.Release()
			}
		}

		t.Reset(r.timeout)
	}
}
