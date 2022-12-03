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

const (
	maxQPSPerNameserver = 100
	successesToRaiseQPS = 5
	rateUpdateInterval  = 3 * time.Second
)

type rateTrack struct {
	sync.Mutex
	qps     int
	rate    ratelimit.Limiter
	success int
	timeout int
}

type serversRateLimiter struct {
	sync.Mutex
	done            chan struct{}
	domainToServers map[string][]string
	serverToLimiter map[string]*rateTrack
	catchLimiter    *rateTrack
}

func newServersRateLimiter() *serversRateLimiter {
	r := &serversRateLimiter{
		done:            make(chan struct{}, 1),
		domainToServers: make(map[string][]string),
		serverToLimiter: make(map[string]*rateTrack),
		catchLimiter:    newRateTracker(),
	}

	go r.updateRateLimiters()
	return r
}

func newRateTracker() *rateTrack {
	return &rateTrack{
		qps:  maxQPSPerNameserver,
		rate: ratelimit.New(maxQPSPerNameserver),
	}
}

func (r *serversRateLimiter) Take(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	rate := tracker.rate
	tracker.Unlock()

	rate.Take()
}

func (r *serversRateLimiter) ReportTimeout(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.timeout++
	tracker.Unlock()
}

func (r *serversRateLimiter) ReportSuccess(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.success++
	tracker.Unlock()
}

func (r *serversRateLimiter) updateRateLimiters() {
	t := time.NewTicker(rateUpdateInterval)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.updateAllRateLimiters()
		}
	}
}

func (r *serversRateLimiter) updateAllRateLimiters() {
	r.Lock()
	defer r.Unlock()

	r.catchLimiter.update()
	for _, rt := range r.serverToLimiter {
		rt.update()
	}
}

func (rt *rateTrack) update() {
	rt.Lock()
	defer rt.Unlock()
	// check if this rate tracker has already been updated
	if rt.success == 0 && rt.timeout == 0 {
		return
	}

	var updated bool
	// any timeouts indicate a need to slow down
	if rt.timeout > 0 {
		rt.qps -= rt.timeout
		if rt.qps <= 0 {
			rt.qps = 1
		}
		updated = true
	}
	// a good number of successes are necessary to warrant an increase
	if !updated && rt.success > 0 {
		if inc := rt.success / successesToRaiseQPS; inc > 0 {
			rt.qps += inc
			updated = true
		} else if inc == 0 && rt.qps <= successesToRaiseQPS {
			rt.qps++
			updated = true
		}
	}

	if updated {
		rt.rate = ratelimit.New(rt.qps)
	}
	rt.success = 0
	rt.timeout = 0
}

func (r *serversRateLimiter) getDomainRateTracker(sub string) *rateTrack {
	r.Lock()
	defer r.Unlock()

	n := strings.ToLower(RemoveLastDot(sub))
	domain, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return r.catchLimiter
	}
	domain = strings.ToLower(RemoveLastDot(domain))

	servers, found := r.domainToServers[domain]
	if !found {
		servers = r.getNameservers(domain)
		r.domainToServers[domain] = servers
	}

	if len(servers) == 0 {
		return r.catchLimiter
	}

	var tracker *rateTrack
	// check if we already have a rate limiter for these servers
	for _, name := range servers {
		if rt, found := r.serverToLimiter[name]; found {
			tracker = rt
			break
		}
	}
	if tracker == nil {
		tracker = newRateTracker()
	}
	// make sure all the servers are using the same rate limiter
	for _, name := range servers {
		if _, found := r.serverToLimiter[name]; !found {
			r.serverToLimiter[name] = tracker
		}
	}
	return tracker
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
