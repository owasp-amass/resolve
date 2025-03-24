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
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

type NewServer func(addr string) types.Nameserver

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

func RootServers(timeout time.Duration, newserver NewServer) []types.Nameserver {
	var servs []types.Nameserver

	for _, ip := range rootIPs {
		if serv := newserver(ip); serv != nil {
			servs = append(servs, serv)
		}
	}

	return servs
}

func NewAuthoritative(timeout time.Duration, newserver NewServer) *authoritative {
	auth := &authoritative{
		done:          make(chan struct{}, 1),
		timeout:       timeout,
		newserver:     newserver,
		lookup:        make(map[string]types.Nameserver),
		fqdnToServers: make(map[string][]string),
		fqdnToNSs:     make(map[string][]types.Nameserver),
		serverToNSs:   make(map[string]types.Nameserver),
	}

	for _, ns := range RootServers(timeout, newserver) {
		addr := ns.Address().IP.String()

		auth.lookup[addr] = ns
		auth.list = append(auth.list, ns)
		auth.roots = append(auth.roots, ns)
	}

	go auth.timeouts()
	return auth
}

// Get performs selection of the correct nameserver in the pool.
func (r *authoritative) Get(fqdn string) types.Nameserver {
	r.Lock()
	defer r.Unlock()

	name := strings.ToLower(utils.RemoveLastDot(fqdn))
	if ns := r.checkFQDNAndMinusOne(name); ns != nil {
		return ns
	}

	r.populateAuthServers(name)
	if res := r.checkFQDNAndMinusOne(name); res != nil {
		return res
	}
	return nil
}

func (r *authoritative) checkFQDNAndMinusOne(fqdn string) types.Nameserver {
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

func (r *authoritative) Lookup(addr string) types.Nameserver {
	r.Lock()
	defer r.Unlock()

	return r.lookup[addr]
}

func (r *authoritative) Add(ns types.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address().IP.String()
	if _, found := r.lookup[addrstr]; !found {
		r.list = append(r.list, ns)
		r.lookup[addrstr] = ns
	}
}

func (r *authoritative) Remove(ns types.Nameserver) {
	r.Lock()
	defer r.Unlock()

	addrstr := ns.Address().IP.String()
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

func (r *authoritative) All() []types.Nameserver {
	r.Lock()
	defer r.Unlock()

	all := make([]types.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	return all
}

func (r *authoritative) Close() {
	close(r.done)

	r.Lock()
	all := make([]types.Nameserver, 0, len(r.list))
	_ = copy(all, r.list)
	r.Unlock()

	for _, ns := range all {
		r.Remove(ns)
		ns.Close()
	}

	r.list = nil
	r.lookup = nil
	r.fqdnToServers = nil
	r.fqdnToNSs = nil
	r.serverToNSs = nil
}

func (r *authoritative) populateAuthServers(fqdn string) {
	labels := strings.Split(fqdn, ".")
	last, resolvers := r.findClosestResolverSet(fqdn, labels[len(labels)-1])

	if len(labels) < len(strings.Split(last, ".")) {
		return
	}

	r.populateFromLabel(last, fqdn, resolvers)
}

func (r *authoritative) populateFromLabel(last, fqdn string, nsers []types.Nameserver) {
	utils.RegisteredToFQDN(last, fqdn, func(name string) bool {
		ns := pickOneServer(nsers)

		servs, found := r.fqdnToServers[name]
		if !found {
			servs = r.getNameServers(name, ns)
			r.fqdnToServers[name] = servs
		}

		var updated bool
		if len(servs) > 0 {
			var servset []types.Nameserver
			type servres struct {
				server string
				ns     types.Nameserver
			}
			results := make(chan *servres, len(servs))
			defer close(results)

			for _, server := range servs {
				go func(n string, ns types.Nameserver) {
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
				addrstr := result.ns.Address().IP.String()
				if _, found := r.lookup[addrstr]; !found {
					r.list = append(r.list, result.ns)
					r.lookup[addrstr] = result.ns
					r.serverToNSs[result.server] = result.ns
				}
			}

			if len(servset) > 0 {
				updated = true
				nsers = servset
			}
		}

		if name != fqdn || updated {
			r.fqdnToNSs[name] = nsers
		}
		return false
	})
}

func (r *authoritative) findClosestResolverSet(fqdn, tld string) (string, []types.Nameserver) {
	last := fqdn
	resolvers := make([]types.Nameserver, len(r.roots))
	_ = copy(resolvers, r.roots)

	utils.FQDNToRegistered(fqdn, tld, func(name string) bool {
		if res, found := r.fqdnToNSs[name]; found {
			resolvers = res
			return true
		}
		last = name
		return false
	})

	return last, resolvers
}

func (r *authoritative) serverNameToResolverObj(server string, ns types.Nameserver) types.Nameserver {
	addr := ns.Address().IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	for i := 0; i < 10; i++ {
		msg := utils.QueryMsg(server, dns.TypeA)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range utils.AnswersByType(m, dns.TypeA) {
				if record, ok := rr.(*dns.A); ok {
					ip := net.JoinHostPort(record.A.String(), "53")
					return r.newserver(ip)
				}
			}
			break
		}
	}
	return nil
}

func (r *authoritative) getNameServers(fqdn string, ns types.Nameserver) []string {
	addr := ns.Address().IP.String() + ":53"
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second,
	}

	var servers []string
	for i := 0; i < 10; i++ {
		msg := utils.QueryMsg(fqdn, dns.TypeNS)

		if m, _, err := client.Exchange(msg, addr); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			for _, rr := range utils.AnswersByType(m, dns.TypeNS) {
				if record, ok := rr.(*dns.NS); ok {
					servers = append(servers, strings.ToLower(utils.RemoveLastDot(record.Ns)))
				}
			}
			break
		}
	}
	return servers
}

func (r *authoritative) timeouts() {
	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}

		r.Lock()
		cp := make([]types.Nameserver, 0, len(r.list))
		_ = copy(cp, r.list)
		r.Unlock()

		for _, ns := range cp {
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

func pickOneServer(servers []types.Nameserver) types.Nameserver {
	if l := len(servers); l > 0 {
		return servers[rand.Intn(l)]
	}
	return nil
}
