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

// NewRateTracker returns an active RateTracker that tracks and rate limits per name server.
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

// Stop will release the RateTracker resources.
func (r *RateTracker) Stop() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
}

// Take blocks as required by the implemented rate limiter for the associated name server.
func (r *RateTracker) Take(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	rate := tracker.rate
	tracker.Unlock()

	rate.Take()
}

// Success signals to the RateTracker that a request for the provided subdomain name was successful.
func (r *RateTracker) Success(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.success++
	tracker.Unlock()
}

// Timeout signals to the RateTracker that a request for the provided subdomain name timed out.
func (r *RateTracker) Timeout(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.timeout++
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

	servers := r.getMappedServers(n, domain)
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

func (r *RateTracker) getMappedServers(sub, domain string) []string {
	var servers []string

	r.deepestZone(sub, domain, func(name string) bool {
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

func (r *RateTracker) deepestNameServers(sub, domain string) ([]string, string) {
	var zone string
	var servers []string

	r.deepestZone(sub, domain, func(name string) bool {
		if s := r.getNameservers(name); len(s) > 0 {
			zone = name
			servers = s
			return true
		}
		return false
	})
	return servers, zone
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

func (r *RateTracker) deepestZone(sub, domain string, callback func(name string) bool) {
	base := len(strings.Split(domain, "."))
	labels := strings.Split(sub, ".")

	// Check for a zone at each label starting with the FQDN
	max := len(labels) - base
	for i := 0; i <= max; i++ {
		if callback(strings.Join(labels[i:], ".")) {
			break
		}
	}
}
