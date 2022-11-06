// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxScanLen int = 10

var rootServers = []string{
	"198.41.0.4",     // Verisign, Inc.
	"199.9.14.201",   // University of Southern California, Information Sciences Institute
	"192.33.4.12",    // Cogent Communications
	"199.7.91.13",    // University of Maryland
	"192.203.230.10", // NASA (Ames Research Center)
	"192.5.5.241",    // Internet Systems Consortium, Inc.
	"192.112.36.4",   // US Department of Defense (NIC)
	"198.97.190.53",  // US Army (Research Lab)
	"192.36.148.17",  // Netnod
	"192.58.128.30",  // Verisign, Inc.
	"193.0.14.129",   // RIPE NCC
	"199.7.83.42",    // ICANN
	"202.12.27.33",   // WIDE Project
}

type selector interface {
	// GetResolver returns a resolver managed by the selector, optionally utilizing the provided name.
	GetResolver(name string) *resolver

	// AddResolver can add a resolver for the provided addr to the selector.
	AddResolver(addr string, timeout time.Duration) error

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
	scan int
}

func newRandomSelector() *randomSelector {
	return new(randomSelector)
}

// GetResolver performs random selection plus short scan for the resolver with shortest queue.
func (r *randomSelector) GetResolver(name string) *resolver {
	var chosen *resolver

	for chosen == nil {
		chosen = r.randomAvailableResolver()

		if chosen == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}

	return chosen
}

func (r *randomSelector) AddResolver(addr string, timeout time.Duration) error {
	r.Lock()
	defer r.Unlock()

	res := initializeResolver(addr, timeout)
	if res == nil {
		return fmt.Errorf("failed to initialize a resolver for %s", addr)
	}

	r.list = append(r.list, res)
	r.scan = min(len(r.list), maxScanLen)
	return nil
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
	r.list = nil
}

func (r *randomSelector) randomAvailableResolver() *resolver {
	rlen := r.Len()
	if rlen == 0 {
		return nil
	}

	now := time.Now()
	var chosen *resolver
	for i := 0; i < rlen; i++ {
		rnd := rand.Intn(rlen)
		res := r.list[rnd]

		if res.last.Add(res.rate).Before(now) {
			chosen = res
			break
		}
	}
	return chosen
}

func min(x, y int) int {
	m := x
	if y < m {
		m = y
	}
	return m
}

type iterativeSelector struct {
	listLock sync.Mutex
	list     []*resolver
	roots    []*resolver
	zoneLock sync.Mutex
	rmap     map[string]*resolver
	zones    map[string][]*resolver
	timeout  time.Duration
}

func newIterativeSelector(timeout time.Duration) *iterativeSelector {
	sel := &iterativeSelector{
		rmap:    make(map[string]*resolver),
		zones:   make(map[string][]*resolver),
		timeout: timeout,
	}

	for _, addr := range rootServers {
		if res := initializeResolver(addr, timeout); res != nil {
			sel.roots = append(sel.roots, res)
		}
	}
	if len(sel.roots) == 0 {
		return nil
	}
	return sel
}

// GetResolver performs random selection plus short scan for the resolver with shortest queue.
func (r *iterativeSelector) GetResolver(name string) *resolver {
	r.zoneLock.Lock()
	defer r.zoneLock.Unlock()

	if list, aa := r.recursiveReferrals(name, strings.Split(name, ".")); aa && len(list) > 0 {
		return r.randomSelection(list)
	}
	return nil
}

func (r *iterativeSelector) AddResolver(addr string, timeout time.Duration) error {
	return errors.New("the iterativeSelector automatically adds only authoritative name servers for desired zones")
}

func (r *iterativeSelector) AllResolvers() []*resolver {
	r.listLock.Lock()
	defer r.listLock.Unlock()

	dst := make([]*resolver, len(r.list))
	copy(dst, r.list)
	return dst
}

// Len returns the number of resolvers that have been added to the pool.
func (r *iterativeSelector) Len() int {
	r.listLock.Lock()
	defer r.listLock.Unlock()

	return len(r.list)
}

func (r *iterativeSelector) Close() {
	r.zoneLock.Lock()
	r.rmap = nil
	r.zones = nil
	r.roots = nil
	r.zoneLock.Unlock()

	r.listLock.Lock()
	r.list = nil
	r.listLock.Unlock()
}

func (r *iterativeSelector) recursiveReferrals(name string, labels []string) ([]*resolver, bool) {
	if len(labels) == 0 {
		return r.roots, false
	}

	sub := strings.Join(labels, ".")
	if servers, found := r.zones[sub]; found {
		return servers, r.processReferral(name, servers)
	}
	if list, aa := r.recursiveReferrals(name, labels[1:]); aa {
		return list, aa
	} else if len(list) > 0 {
		_ = r.processReferral(name, list)
	}
	if servers, found := r.zones[sub]; found {
		return servers, r.processReferral(name, servers)
	}
	return nil, false
}

func (r *iterativeSelector) randomSelection(list []*resolver) *resolver {
	l := len(list)

	return list[rand.Intn(l)]
}

func (r *iterativeSelector) processReferral(name string, list []*resolver) bool {
	var res *resolver
	var resp *dns.Msg
	ch := make(chan *dns.Msg, 1)

	for i := 0; i < 10; i++ {
		res = r.randomSelection(list)
		if res == nil {
			return false
		}

		msg := QueryMsg(name, 1)
		req := reqPool.Get().(*request)
		req.Ctx = context.Background()
		req.ID = msg.Id
		req.Name = name
		req.Qtype = 1
		req.Msg = msg
		req.Result = ch

		res.exchange(req)
		resp = <-ch
		if resp != nil && resp.Rcode != RcodeNoResponse {
			break
		}
	}

	var aa bool
	if resp != nil && resp.Rcode != RcodeNoResponse {
		aa = resp.Authoritative
		if !aa {
			_ = r.checkForDelegation(resp)
		}
	}
	return aa
}

func (r *iterativeSelector) checkForDelegation(resp *dns.Msg) bool {
	if resp.Rcode != dns.RcodeSuccess || resp.Authoritative || len(resp.Answer) > 0 || len(resp.Ns) == 0 {
		return false
	}

	zone := RemoveLastDot(resp.Ns[0].Header().Name)
	if _, found := r.zones[zone]; found {
		return false
	}

	servers := make(map[string]string, len(resp.Ns))
	for _, rr := range resp.Ns {
		name := RemoveLastDot(rr.Header().Name)
		server := parseNSType(rr)
		if name != "" && server != "" {
			servers[name] = server
		}
	}

	addrs := make(map[string]string, len(resp.Extra))
	for _, rr := range resp.Extra {
		name := RemoveLastDot(rr.Header().Name)
		qtype := rr.Header().Rrtype
		if name == "" || qtype != 1 { // TODO: Add check for AAAA record
			continue
		}
		addrs[name] = parseAType(rr)
	}

	var list []*resolver
	for _, server := range servers {
		addr := addrs[server]
		if addr == "" {
			continue
		}
		if res, found := r.rmap[addr]; found {
			list = append(list, res)
			continue
		}
		if res := initializeResolver(addr, r.timeout); res != nil {
			list = append(list, res)
			r.addToList(res)
			r.rmap[addr] = res
		}
	}

	r.zones[zone] = list
	return true
}

func (r *iterativeSelector) addToList(res *resolver) {
	r.listLock.Lock()
	defer r.listLock.Unlock()

	r.list = append(r.list, res)
}
