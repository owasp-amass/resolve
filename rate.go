// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/ratelimit"
	"golang.org/x/net/publicsuffix"
)

const maxQPSPerNameserver = 100

type serversRateLimiter struct {
	sync.Mutex
	domainToServers map[string][]string
	serverToLimiter map[string]ratelimit.Limiter
	catchLimiter    ratelimit.Limiter
}

func newServersRateLimiter() *serversRateLimiter {
	return &serversRateLimiter{
		domainToServers: make(map[string][]string),
		serverToLimiter: make(map[string]ratelimit.Limiter),
		catchLimiter:    ratelimit.New(maxQPSPerNameserver),
	}
}

func (r *serversRateLimiter) Take(sub string) {
	r.Lock()
	defer r.Unlock()

	domain, err := publicsuffix.EffectiveTLDPlusOne(sub)
	if err != nil {
		r.catchLimiter.Take()
		return
	}
	domain = RemoveLastDot(domain)

	servers, found := r.domainToServers[domain]
	if !found {
		servers = r.getNameservers(domain)
		r.domainToServers[domain] = servers
	}

	if len(servers) == 0 {
		r.catchLimiter.Take()
		return
	}

	var limiter ratelimit.Limiter
	// check if we already have a rate limiter for these servers
	for _, name := range servers {
		if l, found := r.serverToLimiter[name]; found {
			limiter = l
			break
		}
	}
	if limiter == nil {
		limiter = ratelimit.New(maxQPSPerNameserver)
	}
	// make sure all the server are using the same rate limiter
	for _, name := range servers {
		r.serverToLimiter[name] = limiter
	}

	limiter.Take()
}

func (r *serversRateLimiter) getNameservers(domain string) []string {
	client := dns.Client{
		Net:     "tcp",
		Timeout: time.Minute,
	}

	var servers []string
	if m, _, err := client.Exchange(QueryMsg(domain, dns.TypeNS), "8.8.8.8:53"); err == nil {
		if ans := ExtractAnswers(m); len(ans) > 0 {
			for _, rr := range AnswersByType(ans, dns.TypeNS) {
				servers = append(servers, strings.ToLower(RemoveLastDot(rr.Data)))
			}
		}
	}
	return servers
}
