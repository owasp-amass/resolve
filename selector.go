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

	addrstr := res.address.IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, res)
		r.lookup[addrstr] = res
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

var rootIPs = []string{
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

type authNSSelector struct {
	sync.Mutex
	update           sync.Mutex
	pool             *Resolvers
	list             []*resolver
	lookup           map[string]*resolver
	rootResolvers    []*resolver
	fqdnToServers    map[string][]string
	fqdnToResolvers  map[string][]*resolver
	serverToResolver map[string]*resolver
}

func newAuthNSSelector(r *Resolvers) *authNSSelector {
	auth := &authNSSelector{
		pool:             r,
		lookup:           make(map[string]*resolver),
		fqdnToServers:    make(map[string][]string),
		fqdnToResolvers:  make(map[string][]*resolver),
		serverToResolver: make(map[string]*resolver),
	}

	for _, addr := range rootIPs {
		if res := r.initResolver(addr); res != nil {
			auth.setLookup(addr, res)
			auth.rootResolvers = append(auth.rootResolvers, res)
		}
	}

	auth.appendToList(auth.rootResolvers)
	return auth
}

// GetResolver performs random selection on the pool of resolvers.
func (r *authNSSelector) GetResolver(fqdn string) *resolver {
	name := strings.ToLower(RemoveLastDot(fqdn))
	labels := strings.Split(name, ".")
	if len(labels) > 1 {
		name = strings.Join(labels[1:], ".")
	}

	servers := r.getFQDNToServers(name)
	if len(servers) == 0 {
		r.update.Lock()
		r.populateAuthServers(name)
		r.update.Unlock()
	}

	resolvers := r.getFQDNToResolvers(name)
	if len(resolvers) > 0 {
		return pickOneResolver(resolvers)
	}
	return nil
}

func (r *authNSSelector) LookupResolver(addr string) *resolver {
	return r.getLookup(addr)
}

func (r *authNSSelector) AddResolver(res *resolver) {
	addrstr := res.address.IP.String()

	if fres := r.getLookup(addrstr); fres == nil {
		r.appendToList([]*resolver{res})
		r.setLookup(addrstr, res)
	}
}

func (r *authNSSelector) AllResolvers() []*resolver {
	list := r.getList()

	var active []*resolver
	for _, res := range list {
		select {
		case <-res.done:
		default:
			active = append(active, res)
		}
	}
	return active
}

func (r *authNSSelector) Len() int {
	list := r.getList()

	var count int
	for _, res := range list {
		select {
		case <-res.done:
		default:
			count++
		}
	}
	return count
}

func (r *authNSSelector) Close() {
	list := r.getList()

	for _, res := range list {
		select {
		case <-res.done:
		default:
			res.stop()
		}
	}

	r.list = nil
	r.lookup = nil
	r.fqdnToServers = nil
	r.fqdnToResolvers = nil
	r.serverToResolver = nil
}

func (r *authNSSelector) populateAuthServers(fqdn string) {
	if s := r.getFQDNToServers(fqdn); len(s) > 0 {
		return
	}

	labels := strings.Split(fqdn, ".")
	last, resolvers := r.findClosestResolverSet(fqdn, labels[len(labels)-1])
	if len(labels) < len(strings.Split(last, ".")) {
		return
	}

	r.populateFromLabel(last, fqdn, resolvers)
}

func (r *authNSSelector) populateFromLabel(last, fqdn string, resolvers []*resolver) {
	RegisteredToFQDN(last, fqdn, func(name string) bool {
		res := pickOneResolver(resolvers)

		if servers := r.getNameServers(name, res); len(servers) > 0 {
			r.setFQDNToServers(name, servers)

			var wg sync.WaitGroup
			var resset []*resolver
			for _, server := range servers {
				wg.Add(1)
				go func(name string, res *resolver) {
					defer wg.Done()

					if fres := r.getServerToResolver(server); fres != nil {
						resset = append(resset, fres)
					} else if nres := r.serverNameToResolverObj(server, res); nres != nil {
						resset = append(resset, nres)
						r.appendToList([]*resolver{nres})
						r.setLookup(nres.address.IP.String(), nres)
						r.setServerToResolver(server, nres)
					}
				}(server, pickOneResolver(resolvers))
			}

			wg.Wait()
			if len(resset) > 0 {
				resolvers = resset
			}
		}

		r.setFQDNToResolvers(name, resolvers)
		return false
	})
}

func (r *authNSSelector) findClosestResolverSet(fqdn, tld string) (string, []*resolver) {
	last := fqdn
	resolvers := make([]*resolver, len(r.rootResolvers))
	_ = copy(resolvers, r.rootResolvers)

	FQDNToRegistered(fqdn, tld, func(name string) bool {
		if res := r.getFQDNToResolvers(name); len(res) > 0 {
			resolvers = res
			return true
		}
		last = name
		return false
	})

	return last, resolvers
}

func (r *authNSSelector) serverNameToResolverObj(server string, res *resolver) *resolver {
	ch := make(chan *dns.Msg, 1)
	defer close(ch)

	for i := 0; i < maxQueryAttempts; i++ {
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
	for i := 0; i < maxQueryAttempts; i++ {
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

func (r *authNSSelector) getList() []*resolver {
	r.Lock()
	defer r.Unlock()

	return r.list
}

func (r *authNSSelector) appendToList(elements []*resolver) {
	r.Lock()
	defer r.Unlock()

	r.list = append(r.list, elements...)
}

func (r *authNSSelector) getLookup(key string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[key]
}

func (r *authNSSelector) setLookup(key string, res *resolver) {
	r.Lock()
	defer r.Unlock()

	r.lookup[key] = res
}

func (r *authNSSelector) getFQDNToServers(key string) []string {
	r.Lock()
	defer r.Unlock()

	return r.fqdnToServers[key]
}

func (r *authNSSelector) setFQDNToServers(key string, servers []string) {
	r.Lock()
	defer r.Unlock()

	r.fqdnToServers[key] = servers
}

func (r *authNSSelector) getFQDNToResolvers(key string) []*resolver {
	r.Lock()
	defer r.Unlock()

	return r.fqdnToResolvers[key]
}

func (r *authNSSelector) setFQDNToResolvers(key string, resolvers []*resolver) {
	r.Lock()
	defer r.Unlock()

	r.fqdnToResolvers[key] = resolvers
}

func (r *authNSSelector) getServerToResolver(key string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.serverToResolver[key]
}

func (r *authNSSelector) setServerToResolver(key string, res *resolver) {
	r.Lock()
	defer r.Unlock()

	r.serverToResolver[key] = res
}

func pickOneResolver(resolvers []*resolver) *resolver {
	if l := len(resolvers); l > 0 {
		return resolvers[rand.Intn(l)]
	}
	return nil
}
