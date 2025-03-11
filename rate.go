// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

const (
	maxQPSPerNameserver = 100
	numIntervalSeconds  = 5
	rateUpdateInterval  = numIntervalSeconds * time.Second
	minUpdateSampleSize = 10
)

type rateTrack struct {
	sync.Mutex
	rate  *rate.Limiter
	avg   time.Duration
	count int
	first bool
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
	limit := rate.Every(100 * time.Millisecond)

	return &rateTrack{
		rate:  rate.NewLimiter(limit, 1),
		first: true,
	}
}

// Stop will release the RateTracker resources.
func (r *RateTracker) Stop() {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
}

// Take blocks as required by the implemented rate limiter for the associated name server.
func (r *RateTracker) Take(sub string) {
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	rate := tracker.rate
	tracker.Unlock()

	_ = rate.Wait(context.TODO())
}

// ReportResponseTime provides the response time for a request for the domain name provided in the sub parameter.
func (r *RateTracker) ReportResponseTime(sub string, delta time.Duration) {
	var average, count float64
	tracker := r.getDomainRateTracker(sub)

	tracker.Lock()
	tracker.count++
	count = float64(tracker.count)
	average = float64(tracker.avg.Milliseconds())
	average = ((average * (count - 1)) + float64(delta.Milliseconds())) / count
	tracker.avg = time.Duration(math.Round(average)) * time.Millisecond

	if tracker.first {
		defer tracker.update()
	}
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

	if rt.first {
		rt.first = false
	} else if rt.count < minUpdateSampleSize {
		return
	}

	limit := rate.Every(rt.avg)
	// update the QPS rate limiter and reset counters
	rt.rate = rate.NewLimiter(limit, 1)
	rt.avg = 0
	rt.count = 0
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

func (r *RateTracker) deepestNameServers(sub, domain string) ([]string, string) {
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

func (r *RateTracker) getNameservers(domain string) []string {
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
