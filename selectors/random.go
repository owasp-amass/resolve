// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"math/rand"

	"github.com/owasp-amass/resolve/types"
)

func NewRandom() *random {
	return &random{lookup: make(map[string]types.Nameserver)}
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
	r.Lock()
	all := make([]types.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	r.Unlock()

	for _, ns := range all {
		r.Remove(ns)
	}

	r.list = nil
	r.lookup = nil
}
