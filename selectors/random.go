// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"errors"
	"math/rand"
	"time"

	"github.com/owasp-amass/resolve/types"
)

func NewRandom(timeout time.Duration, servs ...types.Nameserver) *random {
	if len(servs) == 0 {
		return nil
	}

	r := &random{
		done:    make(chan struct{}, 1),
		timeout: timeout,
		lookup:  make(map[string]types.Nameserver),
	}

	for _, ns := range servs {
		r.list = append(r.list, ns)
		r.lookup[ns.Address().IP.String()] = ns
	}

	go r.timeouts()
	return r
}

// Get performs random selection on the pool of nameservers.
func (r *random) Get(fqdn string) (types.Nameserver, error) {
	select {
	case <-r.done:
		return nil, errors.New("the selector has been closed")
	default:
	}

	if l := len(r.list); l == 0 {
		return nil, errors.New("the selector has no nameservers")
	} else if l == 1 {
		return r.list[0], nil
	}

	sel := rand.Intn(len(r.list))
	return r.list[sel], nil
}

func (r *random) Lookup(addr string) (types.Nameserver, error) {
	select {
	case <-r.done:
		return nil, errors.New("the selector has been closed")
	default:
	}

	if ns, found := r.lookup[addr]; found {
		return ns, nil
	}
	return nil, errors.New("the selector does not have the requested nameserver")
}

func (r *random) All() []types.Nameserver {
	select {
	case <-r.done:
		return nil
	default:
	}
	return r.list
}

func (r *random) Close() {
	close(r.done)

	for _, ns := range r.All() {
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

		for _, ns := range r.All() {
			for _, req := range ns.XchgManager().RemoveExpired(r.timeout) {
				go func(req types.Request) {
					req.NoResponse()
					req.Release()
				}(req)
			}
		}

		t.Reset(r.timeout)
	}
}
