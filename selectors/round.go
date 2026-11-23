// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"errors"
	"time"

	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

// NewRoundRobin returns a selector that owns its nameservers: it expires
// their unanswered queries after timeout, and its Close closes them.
func NewRoundRobin(timeout time.Duration, servs ...types.Nameserver) *roundRobin {
	r := newRoundRobin(false, timeout, servs...)
	if r != nil {
		go r.timeouts()
	}
	return r
}

// NewSharedRoundRobin returns a selector over nameservers that other
// selectors use too, such as those of a servers.Registry. Their owner
// expires their queries, and Close leaves them open.
func NewSharedRoundRobin(servs ...types.Nameserver) *roundRobin {
	return newRoundRobin(true, 0, servs...)
}

func newRoundRobin(shared bool, timeout time.Duration, servs ...types.Nameserver) *roundRobin {
	if len(servs) == 0 {
		return nil
	}

	r := &roundRobin{
		done:    make(chan struct{}, 1),
		shared:  shared,
		timeout: timeout,
		lookup:  make(map[string]types.Nameserver),
	}

	for _, ns := range servs {
		r.list = append(r.list, ns)
		r.lookup[ns.Address().IP.String()] = ns
	}
	return r
}

// Get performs round robin selection on the pool of nameservers.
func (r *roundRobin) Get(fqdn string) (types.Nameserver, error) {
	select {
	case <-r.done:
		return nil, errors.New("the selector has been closed")
	default:
	}

	var idx uint32
	llen := len(r.list)
	if llen == 0 {
		return nil, errors.New("the selector has no nameservers")
	} else if llen > 1 {
		idx = r.nextIndex(uint32(llen))
	}

	return r.list[idx], nil
}

func (r *roundRobin) nextIndex(max uint32) uint32 {
	value := r.current.Add(1)

	if value < max {
		return value
	}

	normalized := value % max
	if normalized == 0 {
		r.current.Add(-max)
		return 0
	}

	return normalized
}

func (r *roundRobin) Lookup(addr string) (types.Nameserver, error) {
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

func (r *roundRobin) All() []types.Nameserver {
	select {
	case <-r.done:
		return nil
	default:
	}
	return r.list
}

func (r *roundRobin) Close() {
	if !r.shared {
		for _, ns := range r.All() {
			ns.Close()
		}
	}
	close(r.done)

	r.list = nil
	r.lookup = nil
}

func (r *roundRobin) timeouts() {
	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}

		for _, ns := range r.All() {
			utils.ExpireRequests(ns, r.timeout)
		}

		t.Reset(r.timeout)
	}
}
