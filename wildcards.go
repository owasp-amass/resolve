// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"sync"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

// Constants related to DNS labels.
const (
	MaxDNSNameLen  = 253
	MaxDNSLabelLen = 63
	MinLabelLen    = 6
	MaxLabelLen    = 24
	LDHChars       = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

const (
	numOfWildcardTests int = 3
	maxQueryAttempts   int = 5
)

var wildcardQueryTypes = []uint16{
	dns.TypeCNAME,
	dns.TypeA,
	dns.TypeAAAA,
}

type wildcard struct {
	sync.Mutex
	Detected bool
	Answers  []*ExtractedAnswer
}

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain.
func UnlikelyName(sub string) string {
	ldh := []rune(LDHChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := MaxDNSNameLen - (len(sub) + 1)
	if l > MaxLabelLen {
		l = MaxLabelLen
	} else if l < MinLabelLen {
		l = MinLabelLen
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	var newlabel string
	l = MinLabelLen + rand.Intn((l-MinLabelLen)+1)
	for i := 0; i < l; i++ {
		sel := rand.Int() % (ldhLen - 1)
		newlabel = newlabel + string(ldh[sel])
	}

	newlabel = strings.Trim(newlabel, "-")
	if newlabel == "" {
		return newlabel
	}
	return newlabel + "." + sub
}

// WildcardDetected returns true when the provided DNS response could be a wildcard match.
func (r *Resolvers) WildcardDetected(ctx context.Context, resp *dns.Msg, domain string) bool {
	if !r.goodDetector() {
		return false
	}

	name := strings.ToLower(RemoveLastDot(resp.Question[0].Name))
	domain = strings.ToLower(RemoveLastDot(domain))
	if labels := strings.Split(name, "."); len(labels) > len(strings.Split(domain, ".")) {
		name = strings.Join(labels[1:], ".")
	}

	var found bool
	// Check for a DNS wildcard at each label starting with the registered domain
	RegisteredToFQDN(domain, name, func(sub string) bool {
		if w := r.getWildcard(ctx, sub); w.respMatchesWildcard(resp) {
			found = true
			return true
		}
		return false
	})
	return found
}

// SetDetectionResolver sets the provided DNS resolver as responsible for wildcard detection.
func (r *Resolvers) SetDetectionResolver(qps int, addr string) {
	r.Lock()
	defer r.Unlock()

	if _, _, err := net.SplitHostPort(addr); err != nil {
		// add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}
	// check that this address will not create a duplicate resolver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		if _, found := r.rmap[uaddr.IP.String()]; found {
			r.detector = r.pool.LookupResolver(uaddr.IP.String())
			return
		}
		if res := r.initializeResolver(qps, addr); res != nil {
			r.rmap[res.address.IP.String()] = struct{}{}
			r.pool.AddResolver(res)
			r.detector = res
		}
	}
}

func (r *Resolvers) getDetectionResolver() *resolver {
	r.Lock()
	defer r.Unlock()

	return r.detector
}

func (r *Resolvers) goodDetector() bool {
	success := true

	if d := r.getDetectionResolver(); d == nil {
		success = false

		if d = r.pool.GetResolver(); d != nil {
			r.SetDetectionResolver(d.qps, d.address.String())

			if r.detector != nil {
				success = true
			}
		}
	}
	return success
}

func (r *Resolvers) getWildcard(ctx context.Context, sub string) *wildcard {
	r.Lock()
	w, found := r.wildcards[sub]
	if !found {
		w = &wildcard{}
		r.wildcards[sub] = w
	}
	r.Unlock()

	if !found {
		w.Lock()
		w.Detected, w.Answers = r.wildcardTest(ctx, sub)
		w.Unlock()
	}
	return w
}

func (w *wildcard) respMatchesWildcard(resp *dns.Msg) bool {
	w.Lock()
	defer w.Unlock()

	if w.Detected {
		if len(w.Answers) == 0 || len(resp.Answer) == 0 {
			return w.Detected
		}

		set := stringset.New()
		defer set.Close()

		insertRecordData(set, ExtractAnswers(resp))
		intersectRecordData(set, w.Answers)
		if set.Len() > 0 {
			return w.Detected
		}
	}
	return false
}

// Determines if the provided subdomain has a DNS wildcard.
func (r *Resolvers) wildcardTest(ctx context.Context, sub string) (bool, []*ExtractedAnswer) {
	var detected bool
	var answers []*ExtractedAnswer

	set := stringset.New()
	defer set.Close()
	// Query multiple times with unlikely names against this subdomain
	for i := 0; i < numOfWildcardTests; i++ {
		var name string
		for {
			name = UnlikelyName(sub)
			if name != "" {
				break
			}
		}

		var ans []*ExtractedAnswer
		for _, t := range wildcardQueryTypes {
			if a := r.makeQueryAttempts(ctx, name, t); len(a) > 0 {
				detected = true
				ans = append(ans, a...)
			}
		}

		if i == 0 {
			insertRecordData(set, ans)
		} else {
			intersectRecordData(set, ans)
		}
		answers = append(answers, ans...)
	}

	already := stringset.New()
	defer already.Close()

	var final []*ExtractedAnswer
	// Create the slice of answers common across all the responses from unlikely name queries
	for _, a := range answers {
		a.Data = strings.Trim(a.Data, ".")

		if set.Has(a.Data) && !already.Has(a.Data) {
			final = append(final, a)
			already.Insert(a.Data)
		}
	}
	if detected {
		r.log.Printf("DNS wildcard detected: Resolver %s: %s", r.detector.address, "*."+sub)
	}
	return detected, final
}

func (r *Resolvers) makeQueryAttempts(ctx context.Context, name string, qtype uint16) []*ExtractedAnswer {
	ch := make(chan *dns.Msg, 1)
	detector := r.getDetectionResolver()
loop:
	for i := 0; i < maxQueryAttempts; i++ {
		req := &request{
			Res:    detector,
			Msg:    QueryMsg(name, qtype),
			Result: ch,
		}

		r.writeReq(req)
		select {
		case <-ctx.Done():
			break loop
		case resp := <-ch:
			// Check if the response indicates that the name does not exist
			if resp.Rcode == dns.RcodeNameError {
				break loop
			}
			if resp.Rcode == dns.RcodeSuccess {
				if len(resp.Answer) == 0 {
					break loop
				}
				return ExtractAnswers(resp)
			}
		}
	}
	return nil
}

func intersectRecordData(set *stringset.Set, ans []*ExtractedAnswer) {
	records := stringset.New()
	defer records.Close()

	for _, a := range ans {
		records.Insert(strings.Trim(a.Data, "."))
	}
	set.Intersect(records)
}

func insertRecordData(set *stringset.Set, ans []*ExtractedAnswer) {
	records := stringset.New()
	defer records.Close()

	for _, a := range ans {
		records.Insert(strings.Trim(a.Data, "."))
	}
	set.Union(records)
}
