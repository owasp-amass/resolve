// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type selector interface {
	// GetResolver returns a resolver managed by the selector.
	GetResolver(fqdn string) *resolver

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
func (r *randomSelector) GetResolver(fqdn string) *resolver {
	r.Lock()
	defer r.Unlock()

	if l := len(r.list); l == 0 {
		return nil
	} else if l == 1 {
		return r.list[0]
	}

	var chosen *resolver
	sel := rand.Intn(len(r.list))
loop:
	for _, res := range r.list[sel:] {
		select {
		case <-res.done:
			continue loop
		default:
		}

		chosen = res
		break
	}
	return chosen
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

type authNSSelector struct {
	sync.Mutex
	list             []*resolver
	lookup           map[string]*resolver
	domainToServers  map[string][]string
	serverToResolver map[string]*resolver
}

func newAuthNSSelector() *authNSSelector {
	return &authNSSelector{
		lookup:           make(map[string]*resolver),
		domainToServers:  make(map[string][]string),
		serverToResolver: make(map[string]*resolver),
	}
}

// GetResolver performs random selection on the pool of resolvers.
func (r *authNSSelector) GetResolver(fqdn string) *resolver {
	r.Lock()
	defer r.Unlock()

	if l := len(r.list); l == 0 {
		return nil
	} else if l == 1 {
		return r.list[0]
	}

	var chosen *resolver
	sel := rand.Intn(len(r.list))
loop:
	for _, res := range r.list[sel:] {
		select {
		case <-res.done:
			continue loop
		default:
		}

		chosen = res
		break
	}
	return chosen
}

func (r *authNSSelector) LookupResolver(addr string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *authNSSelector) AddResolver(res *resolver) {
	r.Lock()
	defer r.Unlock()

	if _, found := r.lookup[res.address.IP.String()]; !found {
		r.list = append(r.list, res)
		r.lookup[res.address.IP.String()] = res
	}
}

func (r *authNSSelector) AllResolvers() []*resolver {
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

func (r *authNSSelector) Len() int {
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

func (r *authNSSelector) Close() {
	r.Lock()
	defer r.Unlock()

	r.list = nil
	r.lookup = nil
}

func (r *authNSSelector) getDomainResolver(sub string) *resolver {
	n := strings.ToLower(RemoveLastDot(sub))

	domain, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return nil
	}
	domain = strings.ToLower(RemoveLastDot(domain))

	servers := r.getMappedServers(n, domain)
	if len(servers) == 0 {
		return nil
	}

	var resolvers []*resolver
	// check if we already have these servers
	for _, name := range servers {
		if res, found := r.serverToResolver[name]; found {
			resolvers = append(resolvers, res)
		}
	}
	if len(resolvers) == 0 {
		return nil
	}

	return pickOneResolver(resolvers)
}

func (r *authNSSelector) getMappedServers(sub, domain string) []string {
	var servers []string

	FQDNToRegistered(sub, domain, func(name string) bool {
		if serv, found := r.domainToServers[name]; found {
			servers = serv
			return true
		}
		return false
	})

	if len(servers) == 0 {
		if servs, zone := r.deepestNameServers(sub, domain); zone != "" && len(servs) > 0 {
			r.domainToServers[zone] = servs
			servers = servs
		}
	}
	return servers
}

func (r *authNSSelector) deepestNameServers(sub, domain string) ([]string, string) {
	var zone string
	var servers []string

	FQDNToRegistered(sub, domain, func(name string) bool {
		var found bool
		if s := r.getNameservers(name); len(s) > 0 {
			zone = name
			servers = s
			found = true
		}
		return found
	})
	return servers, zone
}

func (r *authNSSelector) getNameservers(domain string) []string {
	client := dns.Client{
		Net:     "tcp",
		Timeout: time.Minute,
	}

	var servers []string
	if m, _, err := client.Exchange(QueryMsg(domain, dns.TypeNS), "8.8.8.8:53"); err == nil && m != nil {
		for _, rr := range AnswersByType(m, dns.TypeNS) {
			if ns, ok := rr.(*dns.NS); ok {
				servers = append(servers, strings.ToLower(RemoveLastDot(ns.Ns)))
			}
		}
	}
	return servers
}

func pickOneResolver(resolvers []*resolver) *resolver {
	if l := len(resolvers); l > 0 {
		return resolvers[rand.Intn(l)]
	}
	return nil
}
