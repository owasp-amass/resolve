// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve"
)

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

func NewAuthoritative(timeout time.Duration) *Authoritative {
	auth := &Authoritative{
		timeout:       timeout,
		lookup:        make(map[string]*resolve.Nameserver),
		fqdnToServers: make(map[string][]string),
		fqdnToNSs:     make(map[string][]*resolve.Nameserver),
		serverToNSs:   make(map[string]*resolve.Nameserver),
	}

	for _, addr := range rootIPs {
		if ns := resolve.NewNameserver(addr, timeout); ns != nil {
			auth.lookup[addr] = ns
			auth.list = append(auth.list, ns)
			auth.roots = append(auth.roots, ns)
		}
	}
	return auth
}

// Get performs selection of the correct nameserver in the pool.
func (r *Authoritative) Get(fqdn string) *resolve.Nameserver {
	r.Lock()
	defer r.Unlock()

	name := strings.ToLower(resolve.RemoveLastDot(fqdn))
	if ns := r.checkFQDNAndMinusOne(name); ns != nil {
		return ns
	}

	r.populateAuthServers(name)
	if res := r.checkFQDNAndMinusOne(name); res != nil {
		return res
	}
	return nil
}

func (r *Authoritative) checkFQDNAndMinusOne(fqdn string) *resolve.Nameserver {
	if servers, found := r.fqdnToNSs[fqdn]; found {
		return pickOneServer(servers)
	}

	labels := strings.Split(fqdn, ".")
	if len(labels) > 1 {
		fqdn = strings.Join(labels[1:], ".")
	}

	if servers, found := r.fqdnToNSs[fqdn]; found {
		return pickOneServer(servers)
	}
	return nil
}

func (r *Authoritative) Lookup(addr string) *resolve.Nameserver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *Authoritative) Add(ns *resolve.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address.IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, ns)
		r.lookup[addrstr] = ns
	}
}

func (r *Authoritative) Remove(ns *resolve.Nameserver) {
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

func (r *Authoritative) All() []*resolve.Nameserver {
	r.Lock()
	defer r.Unlock()

	all := make([]*resolve.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	return all
}

func (r *Authoritative) Close() {
	r.Lock()
	all := make([]*resolve.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	r.Unlock()

	for _, ns := range all {
		r.Remove(ns)
	}

	r.list = nil
	r.lookup = nil
	r.fqdnToServers = nil
	r.fqdnToNSs = nil
	r.serverToNSs = nil
}

func (r *Authoritative) populateAuthServers(fqdn string) {
	labels := strings.Split(fqdn, ".")
	last, resolvers := r.findClosestResolverSet(fqdn, labels[len(labels)-1])

	if len(labels) < len(strings.Split(last, ".")) {
		return
	}

	r.populateFromLabel(last, fqdn, resolvers)
}

func (r *Authoritative) populateFromLabel(last, fqdn string, servers []*resolve.Nameserver) {
	resolve.RegisteredToFQDN(last, fqdn, func(name string) bool {
		ns := pickOneServer(servers)

		servs, found := r.fqdnToServers[name]
		if !found {
			servs = r.getNameServers(name, ns)
			r.fqdnToServers[name] = servs
		}

		var updated bool
		if len(servs) > 0 {
			var servset []*resolve.Nameserver
			type servres struct {
				server string
				ns     *resolve.Nameserver
			}
			results := make(chan *servres, len(servs))
			defer close(results)

			for _, server := range servs {
				go func(n string, ns *resolve.Nameserver) {
					result := &servres{server: n, ns: nil}

					if fres, found := r.serverToNSs[n]; found {
						result.ns = fres
					} else if nres := r.serverNameToResolverObj(n, ns); nres != nil {
						result.ns = nres
					}

					results <- result
				}(server, ns)
			}

			for i := 0; i < len(servs); i++ {
				result := <-results
				if result == nil || result.ns == nil {
					continue
				}

				servset = append(servset, result.ns)
				addrstr := result.ns.Address.IP.String()
				if _, found := r.lookup[addrstr]; !found {
					r.list = append(r.list, result.ns)
					r.lookup[addrstr] = result.ns
					r.serverToNSs[result.server] = result.ns
				}
			}

			if len(servset) > 0 {
				updated = true
				servers = servset
			}
		}

		if name != fqdn || updated {
			r.fqdnToNSs[name] = servers
		}
		return false
	})
}

func (r *Authoritative) findClosestResolverSet(fqdn, tld string) (string, []*resolve.Nameserver) {
	last := fqdn
	resolvers := make([]*resolve.Nameserver, len(r.roots))
	_ = copy(resolvers, r.roots)

	resolve.FQDNToRegistered(fqdn, tld, func(name string) bool {
		if res, found := r.fqdnToNSs[name]; found {
			resolvers = res
			return true
		}
		last = name
		return false
	})

	return last, resolvers
}

func (r *Authoritative) serverNameToResolverObj(server string, ns *resolve.Nameserver) *resolve.Nameserver {
	addr := ns.Address.IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	for i := 0; i < 10; i++ {
		msg := resolve.QueryMsg(server, dns.TypeA)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range resolve.AnswersByType(m, dns.TypeA) {
				if record, ok := rr.(*dns.A); ok {
					ip := net.JoinHostPort(record.A.String(), "53")
					return resolve.NewNameserver(ip, r.timeout)
				}
			}
			break
		}
	}
	return nil
}

func (r *Authoritative) getNameServers(fqdn string, ns *resolve.Nameserver) []string {
	addr := ns.Address.IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	var servers []string
	for i := 0; i < 10; i++ {
		msg := resolve.QueryMsg(fqdn, dns.TypeNS)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range resolve.AnswersByType(m, dns.TypeNS) {
				if record, ok := rr.(*dns.NS); ok {
					servers = append(servers, strings.ToLower(resolve.RemoveLastDot(record.Ns)))
				}
			}
			break
		}
	}
	return servers
}

func pickOneServer(servers []*resolve.Nameserver) *resolve.Nameserver {
	if l := len(servers); l > 0 {
		return servers[rand.Intn(l)]
	}
	return nil
}
