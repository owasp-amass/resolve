// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

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
			auth.lookup[addr] = res
			auth.list = append(auth.list, res)
			auth.rootResolvers = append(auth.rootResolvers, res)
		}
	}
	return auth
}

// GetResolver performs random selection on the pool of resolvers.
func (r *authNSSelector) GetResolver(fqdn string) *resolver {
	r.Lock()
	defer r.Unlock()

	name := strings.ToLower(RemoveLastDot(fqdn))
	if res := r.checkFQDNAndMinusOne(name); res != nil {
		return res
	}

	r.populateAuthServers(name)
	if res := r.checkFQDNAndMinusOne(name); res != nil {
		return res
	}
	return nil
}

func (r *authNSSelector) checkFQDNAndMinusOne(fqdn string) *resolver {
	if res, found := r.fqdnToResolvers[fqdn]; found {
		return pickOneResolver(res)
	}

	labels := strings.Split(fqdn, ".")
	if len(labels) > 1 {
		fqdn = strings.Join(labels[1:], ".")
	}

	if res, found := r.fqdnToResolvers[fqdn]; found {
		return pickOneResolver(res)
	}
	return nil
}

func (r *authNSSelector) LookupResolver(addr string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *authNSSelector) AddResolver(res *resolver) {
	r.Lock()
	defer r.Unlock()

	addrstr := res.address.IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, res)
		r.lookup[addrstr] = res
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

	for _, res := range r.list {
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

		servers, found := r.fqdnToServers[name]
		if !found {
			servers = r.getNameServers(name, res)
			r.fqdnToServers[name] = servers
		}

		var updated bool
		if len(servers) > 0 {
			var resset []*resolver
			type servres struct {
				server string
				res    *resolver
			}
			results := make(chan *servres, len(servers))
			defer close(results)

			for _, server := range servers {
				go func(name string, res *resolver) {
					result := &servres{server: name, res: nil}

					if fres, found := r.serverToResolver[server]; found {
						result.res = fres
					} else if nres := r.serverNameToResolverObj(server, res); nres != nil {
						result.res = nres
					}

					results <- result
				}(server, pickOneResolver(resolvers))
			}

			for i := 0; i < len(servers); i++ {
				result := <-results
				if result == nil || result.res == nil {
					continue
				}

				resset = append(resset, result.res)
				addrstr := result.res.address.IP.String()
				if _, found := r.lookup[addrstr]; !found {
					r.list = append(r.list, result.res)
					r.lookup[addrstr] = result.res
					r.serverToResolver[result.server] = result.res
				}
			}

			if len(resset) > 0 {
				updated = true
				resolvers = resset
			}
		}

		if name != fqdn || updated {
			r.fqdnToResolvers[name] = resolvers
		}
		return false
	})
}

func (r *authNSSelector) findClosestResolverSet(fqdn, tld string) (string, []*resolver) {
	last := fqdn
	resolvers := make([]*resolver, len(r.rootResolvers))
	_ = copy(resolvers, r.rootResolvers)

	FQDNToRegistered(fqdn, tld, func(name string) bool {
		if res, found := r.fqdnToResolvers[name]; found {
			resolvers = res
			return true
		}
		last = name
		return false
	})

	return last, resolvers
}

func (r *authNSSelector) serverNameToResolverObj(server string, res *resolver) *resolver {
	addr := res.address.IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	for i := 0; i < maxQueryAttempts; i++ {
		msg := QueryMsg(server, dns.TypeA)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range AnswersByType(m, dns.TypeA) {
				if record, ok := rr.(*dns.A); ok {
					ip := net.JoinHostPort(record.A.String(), "53")
					return r.pool.initResolver(ip)
				}
			}
			break
		}
	}
	return nil
}

func (r *authNSSelector) getNameServers(fqdn string, res *resolver) []string {
	addr := res.address.IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	var servers []string
	for i := 0; i < maxQueryAttempts; i++ {
		msg := QueryMsg(fqdn, dns.TypeNS)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range AnswersByType(m, dns.TypeNS) {
				if record, ok := rr.(*dns.NS); ok {
					servers = append(servers, strings.ToLower(RemoveLastDot(record.Ns)))
				}
			}
			break
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
