// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wildcards

import (
	"context"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
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

type Detector struct {
	sync.Mutex
	log       *log.Logger
	server    types.Nameserver
	conns     types.Conn
	wildcards map[string]*wildcard
}

type wildcard struct {
	sync.Mutex
	Detected bool
	Answers  []dns.RR
}

func NewDetector(serv types.Nameserver, conns types.Conn, logger *log.Logger) *Detector {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &Detector{
		log:       logger,
		server:    serv,
		conns:     conns,
		wildcards: make(map[string]*wildcard),
	}
}

// WildcardDetected returns true when the provided DNS response could be a wildcard match.
func (r *Detector) WildcardDetected(ctx context.Context, resp *dns.Msg, domain string) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))
	domain = strings.ToLower(utils.RemoveLastDot(domain))
	if labels := strings.Split(name, "."); len(labels) > len(strings.Split(domain, ".")) {
		name = strings.Join(labels[1:], ".")
	}

	var found bool
	// Check for a DNS wildcard at each label starting with the registered domain
	utils.RegisteredToFQDN(domain, name, func(sub string) bool {
		if w := r.getWildcard(ctx, sub); w.respMatchesWildcard(resp) {
			found = true
			return true
		}
		return false
	})
	return found
}

func (r *Detector) getWildcard(ctx context.Context, sub string) *wildcard {
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

		insertRecordData(set, resp.Answer)
		intersectRecordData(set, w.Answers)
		if set.Len() > 0 {
			return w.Detected
		}
	}
	return false
}

// Determines if the provided subdomain has a DNS wildcard.
func (r *Detector) wildcardTest(ctx context.Context, sub string) (bool, []dns.RR) {
	var detected bool
	var answers []dns.RR

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

		var ans []dns.RR
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

	var final []dns.RR
	// Create the slice of answers common across all the responses from unlikely name queries
	for _, a := range answers {
		var data string

		if a.Header().Rrtype == dns.TypeCNAME {
			data = utils.RemoveLastDot((a.(*dns.CNAME)).Target)
		} else if a.Header().Rrtype == dns.TypeA {
			data = (a.(*dns.A)).A.String()
		} else if a.Header().Rrtype == dns.TypeAAAA {
			data = (a.(*dns.AAAA)).AAAA.String()
		}

		if set.Has(data) && !already.Has(data) {
			final = append(final, a)
			already.Insert(data)
		}
	}
	if detected {
		r.log.Printf("DNS wildcard detected: Resolver %s: %s", r.server.Address(), "*."+sub)
	}
	return detected, final
}

func (r *Detector) makeQueryAttempts(ctx context.Context, name string, qtype uint16) []dns.RR {
loop:
	for i := 0; i < maxQueryAttempts; i++ {
		ch := make(chan *dns.Msg, 1)
		defer close(ch)

		req := types.NewRequest(utils.QueryMsg(name, qtype), ch)
		if err := r.server.SendRequest(req, r.conns); err != nil {
			req.Release()
			continue
		}

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
				return resp.Answer
			}
		}
	}
	return nil
}

func intersectRecordData(set *stringset.Set, ans []dns.RR) {
	records := stringset.New()
	defer records.Close()

	for _, a := range ans {
		if a.Header().Rrtype == dns.TypeCNAME {
			records.Insert(utils.RemoveLastDot((a.(*dns.CNAME)).Target))
		} else if a.Header().Rrtype == dns.TypeA {
			records.Insert((a.(*dns.A)).A.String())
		} else if a.Header().Rrtype == dns.TypeAAAA {
			records.Insert((a.(*dns.AAAA)).AAAA.String())
		}
	}

	set.Intersect(records)
}

func insertRecordData(set *stringset.Set, ans []dns.RR) {
	for _, a := range ans {
		if a.Header().Rrtype == dns.TypeCNAME {
			set.Insert(utils.RemoveLastDot((a.(*dns.CNAME)).Target))
		} else if a.Header().Rrtype == dns.TypeA {
			set.Insert((a.(*dns.A)).A.String())
		} else if a.Header().Rrtype == dns.TypeAAAA {
			set.Insert((a.(*dns.AAAA)).AAAA.String())
		}
	}
}
