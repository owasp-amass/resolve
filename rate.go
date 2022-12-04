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
	numIntervalSeconds  = 3
	rateUpdateInterval  = numIntervalSeconds * time.Second
)

type rateTrack struct {
	sync.Mutex
	qps     int
	rate    ratelimit.Limiter
	success int
	timeout int
}

type RateTracker struct {
	sync.Mutex
	done            chan struct{}
	domainToServers map[string][]string
	serverToLimiter map[string]*rateTrack
	catchLimiter    *rateTrack
}

func NewRateTracker() *RateTracker {
	r := &RateTracker{
		done:            make(chan struct{}, 1),
		domainToServers: make(map[string][]string),
		serverToLimiter: make(map[string]*rateTrack),
		catchLimiter:    newRateTrack(),
	}

	go r.updateRateLimiters()
	return r
}

func newRateTrack() *rateTrack {
	return &rateTrack{
		qps:  maxQPSPerNameserver,
		rate: ratelimit.New(maxQPSPerNameserver),
	}
}

func (r *RateTracker) take(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	rate := tracker.rate
	tracker.Unlock()

	rate.Take()
}

func (r *RateTracker) timeout(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.timeout++
	tracker.Unlock()
}

func (r *RateTracker) success(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.success++
	tracker.Unlock()
}

func (r *RateTracker) updateRateLimiters() {
	t := time.NewTimer(rateUpdateInterval)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.updateAllRateLimiters()
			t.Reset(rateUpdateInterval)
		}
	}
}

func (r *RateTracker) updateAllRateLimiters() {
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
	// timeouts in excess of 5% indicate a need to slow down
	if float64(rt.timeout)/float64(rt.success+rt.timeout) > 0.05 {
		rt.qps--
		if rt.qps <= 0 {
			rt.qps = 1
		}
		updated = true
	}
	// a good number of successes are necessary to warrant an increase
	if !updated && rt.success > 0 {
		if blocks := rt.success / successesToRaiseQPS; blocks > 0 {
			if inc := blocks / numIntervalSeconds; inc > 0 {
				rt.qps += inc
				updated = true
			}
		} else if blocks == 0 && rt.qps <= successesToRaiseQPS {
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

func (r *RateTracker) getDomainRateTracker(sub string) *rateTrack {
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
		tracker = newRateTrack()
	}
	// make sure all the servers are using the same rate limiter
	for _, name := range servers {
		if _, found := r.serverToLimiter[name]; !found {
			r.serverToLimiter[name] = tracker
		}
	}
	return tracker
}

func (r *RateTracker) getNameservers(domain string) []string {
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
