// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math/rand"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
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

	for _, res := range r.list {
		select {
		case <-res.done:
		default:
			res.stop()
		}
	}

	r.list = nil
	r.lookup = nil
}

type authNSSelector struct {
	sync.Mutex
	pool             *Resolvers
	root             *resolver
	list             []*resolver
	lookup           map[string]*resolver
	domainToServers  map[string][]string
	fqdnToResolvers  map[string][]*resolver
	serverToResolver map[string]*resolver
}

func newAuthNSSelector(r *Resolvers) *authNSSelector {
	addr := "8.8.8.8:53"
	google := r.initResolver(addr)
	host, _, _ := net.SplitHostPort(addr)

	return &authNSSelector{
		pool:             r,
		root:             google,
		list:             []*resolver{google},
		lookup:           map[string]*resolver{host: google},
		domainToServers:  make(map[string][]string),
		fqdnToResolvers:  make(map[string][]*resolver),
		serverToResolver: make(map[string]*resolver),
	}
}

// GetResolver performs random selection on the pool of resolvers.
func (r *authNSSelector) GetResolver(fqdn string) *resolver {
	r.Lock()
	defer r.Unlock()

	n := strings.ToLower(RemoveLastDot(fqdn))
	name := n
	labels := strings.Split(n, ".")
	if len(labels) > 1 {
		name = strings.Join(labels[1:], ".")
	}

	if _, found := r.domainToServers[name]; !found {
		r.populateAuthServers(name)
	}

	if res, found := r.fqdnToResolvers[name]; found {
		return pickOneResolver(res)
	}
	return nil
}

func (r *authNSSelector) LookupResolver(addr string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *authNSSelector) AddResolver(res *resolver) {}

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

	for _, res := range r.list {
		select {
		case <-res.done:
		default:
			res.stop()
		}
	}

	r.list = nil
	r.lookup = nil
	r.domainToServers = nil
	r.fqdnToResolvers = nil
	r.serverToResolver = nil
}

func (r *authNSSelector) populateAuthServers(fqdn string) {
	labels := strings.Split(fqdn, ".")
	tld := labels[len(labels)-1]

	var last string
	var resolvers []*resolver
	FQDNToRegistered(fqdn, tld, func(name string) bool {
		if res, found := r.fqdnToResolvers[name]; found {
			resolvers = res
			return true
		}
		last = name
		return false
	})

	if ll := len(labels); ll-1 < len(strings.Split(last, ".")) {
		return
	}

	RegisteredToFQDN(last, fqdn, func(name string) bool {
		res := pickOneResolver(resolvers)

		if servers := r.getNameServers(name, res); len(servers) > 0 {
			r.domainToServers[name] = servers

			var resset []*resolver
			for _, server := range servers {
				if res, found := r.serverToResolver[server]; found {
					resset = append(resset, res)
				} else {
					if res := r.serverNameToResolverObj(server, res); res != nil {
						resset = append(resset, res)
						r.serverToResolver[server] = res
						r.list = append(r.list, res)
						r.lookup[res.address.IP.String()] = res
					}
				}
			}

			if len(resset) > 0 {
				resolvers = resset
			}
		}

		r.fqdnToResolvers[name] = resolvers
		return false
	})
}

func (r *authNSSelector) serverNameToResolverObj(server string, res *resolver) *resolver {
	ch := make(chan *dns.Msg, 1)
	defer close(ch)

	for i := 0; i < 5; i++ {
		req := request{
			Res:    res,
			Msg:    QueryMsg(server, dns.TypeA),
			Result: ch,
		}
		res.queue.Append(&req)

		select {
		case <-res.done:
			return nil
		case resp := <-ch:
			if resp != nil && resp.Rcode == dns.RcodeSuccess {
				for _, rr := range AnswersByType(resp, dns.TypeA) {
					if addr, ok := rr.(*dns.A); ok {
						addr := net.JoinHostPort(addr.A.String(), "53")

						return r.pool.initResolver(addr)
					}
				}
				return nil
			}
		}
	}
	return nil
}

func (r *authNSSelector) getNameServers(fqdn string, res *resolver) []string {
	ch := make(chan *dns.Msg, 1)
	defer close(ch)

	var servers []string
loop:
	for i := 0; i < 5; i++ {
		req := request{
			Res:    res,
			Msg:    QueryMsg(fqdn, dns.TypeNS),
			Result: ch,
		}
		res.queue.Append(&req)

		select {
		case <-res.done:
			return nil
		case resp := <-ch:
			if resp != nil && resp.Rcode == dns.RcodeSuccess {
				for _, rr := range AnswersByType(resp, dns.TypeNS) {
					if record, ok := rr.(*dns.NS); ok {
						servers = append(servers, strings.ToLower(RemoveLastDot(record.Ns)))
					}
				}
				break loop
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
