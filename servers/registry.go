// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

// Registry holds one nameserver per address for any number of pools to
// share, so a nameserver's limits hold across all of them. Pools select its
// nameservers with selectors.NewSharedRoundRobin, which leaves them open, and
// the registry expires their unanswered queries itself.
type Registry struct {
	sync.Mutex
	done    chan struct{}
	timeout time.Duration
	qps     int
	servers map[string]*nameserver
}

// NewRegistry returns a registry whose nameservers give up on a query after
// timeout and take at most qps queries per second each (no cap when qps is
// zero or less).
func NewRegistry(timeout time.Duration, qps int) *Registry {
	r := &Registry{
		done:    make(chan struct{}),
		timeout: timeout,
		qps:     qps,
		servers: make(map[string]*nameserver),
	}

	go r.expire()
	return r
}

// Get returns the registry's nameserver for the address, an IP address with
// an optional port (53 when none is given), adding it on first use.
func (r *Registry) Get(addr string) (types.Nameserver, error) {
	key, err := registryKey(addr)
	if err != nil {
		return nil, err
	}

	r.Lock()
	defer r.Unlock()

	select {
	case <-r.done:
		return nil, errors.New("the registry has been closed")
	default:
	}

	if ns, found := r.servers[key]; found {
		return ns, nil
	}

	ns := newNameserver(key)
	if ns == nil {
		return nil, fmt.Errorf("the nameserver %q cannot be used", addr)
	}
	ns.rate.setMaxQPS(r.qps)
	r.servers[key] = ns
	return ns, nil
}

// SetMaxQPS caps the queries per second sent to each of the registry's
// nameservers, now and when added later. Zero or less removes the cap.
func (r *Registry) SetMaxQPS(qps int) {
	r.Lock()
	defer r.Unlock()

	r.qps = qps
	for _, ns := range r.servers {
		ns.rate.setMaxQPS(qps)
	}
}

// MaxQPS returns the cap on queries per second per nameserver, zero or less
// when there is none.
func (r *Registry) MaxQPS() int {
	r.Lock()
	defer r.Unlock()

	return r.qps
}

// Close stops the expiry and closes the nameservers, ending their queries.
func (r *Registry) Close() {
	r.Lock()
	defer r.Unlock()

	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)

	for _, ns := range r.servers {
		ns.Close()
	}
	r.servers = make(map[string]*nameserver)
}

func (r *Registry) expire() {
	t := time.NewTicker(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}

		r.Lock()
		servs := make([]*nameserver, 0, len(r.servers))
		for _, ns := range r.servers {
			servs = append(servs, ns)
		}
		r.Unlock()

		for _, ns := range servs {
			utils.ExpireRequests(ns, r.timeout)
		}
	}
}

// registryKey returns the address as ip:port. The host must be an IP address,
// so a registry never resolves a name.
func registryKey(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), nil
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("the nameserver %q is not an IP address", addr)
	}
	return netip.AddrPortFrom(ip.Unmap(), 53).String(), nil
}
