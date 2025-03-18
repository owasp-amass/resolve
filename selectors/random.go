// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"math/rand"

	"github.com/owasp-amass/resolve"
)

func NewRandom() *Random {
	return &Random{lookup: make(map[string]*resolve.Nameserver)}
}

// Get performs random selection on the pool of nameservers.
func (r *Random) Get(fqdn string) *resolve.Nameserver {
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

func (r *Random) Lookup(addr string) *resolve.Nameserver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *Random) Add(ns *resolve.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address.IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, ns)
		r.lookup[addrstr] = ns
	}
}

func (r *Random) Remove(ns *resolve.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address.IP.String()
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

func (r *Random) All() []*resolve.Nameserver {
	r.Lock()
	defer r.Unlock()

	all := make([]*resolve.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	return all
}

func (r *Random) Close() {
	r.Lock()
	all := make([]*resolve.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	r.Unlock()

	for _, ns := range all {
		r.Remove(ns)
	}

	r.list = nil
	r.lookup = nil
}
