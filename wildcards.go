// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/caffix/queue"
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

const numOfWildcardTests = 3

// Names for the different types of wildcards that can be detected.
const (
	WildcardTypeNone = iota
	WildcardTypeStatic
	WildcardTypeDynamic
)

var wildcardQueryTypes = []uint16{
	dns.TypeCNAME,
	dns.TypeA,
	dns.TypeAAAA,
}

type wildcard struct {
	WildcardType int
	Answers      []*ExtractedAnswer
	beingTested  bool
}

type wildcardChans struct {
	WildcardReq     queue.Queue
	IPsAcrossLevels chan *ipsAcrossLevels
	TestResult      chan *testResult
}

type wildcardReq struct {
	Ctx   context.Context
	Sub   string
	Start time.Time
	Ch    chan *wildcard
}

type ipsAcrossLevels struct {
	Name    string
	Domain  string
	Records []*ExtractedAnswer
	Ch      chan int
}

type testResult struct {
	Sub    string
	Result *wildcard
}

// WildcardType returns the DNS wildcard type for the provided subdomain name.
func (r *Resolvers) WildcardType(ctx context.Context, msg *dns.Msg, domain string) int {
	return r.wildcard(ctx, r.list[0], msg, domain)
}

func (r *Resolvers) wildcard(ctx context.Context, res *resolver, msg *dns.Msg, domain string) int {
	name := strings.ToLower(RemoveLastDot(msg.Question[0].Name))
	domain = strings.ToLower(RemoveLastDot(domain))

	base := len(strings.Split(domain, "."))
	labels := strings.Split(name, ".")
	if len(labels) > base {
		labels = labels[1:]
	}

	// Check for a DNS wildcard at each label starting with the root domain
	for i := len(labels) - base; i >= 0; i-- {
		w := r.fetchWildcardType(ctx, strings.Join(labels[i:], "."))

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(msg.Answer) == 0 {
				return w.WildcardType
			}

			set := stringset.New()
			defer set.Close()

			insertRecordData(set, ExtractAnswers(msg))
			intersectRecordData(set, w.Answers)
			if set.Len() > 0 {
				return w.WildcardType
			}
		}
	}

	return r.checkIPsAcrossLevels(&ipsAcrossLevels{
		Name:    name,
		Domain:  domain,
		Records: ExtractAnswers(msg),
	})
}

func (r *Resolvers) manageWildcards() {
	wildcards := make(map[string]*wildcard)

	for {
		select {
		case <-r.done:
			return
		case <-r.wildChans.WildcardReq.Signal():
			if element, ok := r.wildChans.WildcardReq.Next(); ok {
				r.wildcardRequest(wildcards, element.(*wildcardReq))
			}
		case test := <-r.wildChans.TestResult:
			wildcards[test.Sub] = test.Result
		case ips := <-r.wildChans.IPsAcrossLevels:
			r.testIPsAcrossLevels(wildcards, ips)
		}
	}
}

func (r *Resolvers) fetchWildcardType(ctx context.Context, sub string) *wildcard {
	ch := make(chan *wildcard, 2)

	r.wildChans.WildcardReq.Append(&wildcardReq{
		Ctx:   ctx,
		Sub:   sub,
		Start: time.Now(),
		Ch:    ch,
	})

	return <-ch
}

func (r *Resolvers) checkIPsAcrossLevels(req *ipsAcrossLevels) int {
	ch := make(chan int, 2)

	req.Ch = ch
	r.wildChans.IPsAcrossLevels <- req

	return <-ch
}

func (r *Resolvers) wildcardRequest(wildcards map[string]*wildcard, req *wildcardReq) {
	// Check if this test should timeout
	if time.Now().After(req.Start.Add(30 * time.Second)) {
		wildcards[req.Sub] = &wildcard{
			WildcardType: WildcardTypeDynamic,
			Answers:      []*ExtractedAnswer{},
			beingTested:  false,
		}
		req.Ch <- wildcards[req.Sub]
		return
	}
	// Check if the wildcard information has been cached
	if w, found := wildcards[req.Sub]; found && !w.beingTested {
		req.Ch <- w
		return
	} else if found && w.beingTested {
		// Wait for the test to complete
		go r.delayAppend(req)
		return
	}
	// Start the DNS wildcard test for this subdomain
	wildcards[req.Sub] = &wildcard{
		WildcardType: WildcardTypeNone,
		Answers:      []*ExtractedAnswer{},
		beingTested:  true,
	}
	go r.wildcardTest(req.Ctx, req.Sub)
	go r.delayAppend(req)
}

func (r *Resolvers) delayAppend(req *wildcardReq) {
	time.Sleep(time.Second)
	r.wildChans.WildcardReq.Append(req)
}

func (r *Resolvers) testIPsAcrossLevels(wildcards map[string]*wildcard, req *ipsAcrossLevels) {
	if len(req.Records) == 0 {
		req.Ch <- WildcardTypeNone
		return
	}

	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(strings.ToLower(req.Name), ".")
	if len(labels) <= base || (len(labels)-base) < 3 {
		req.Ch <- WildcardTypeNone
		return
	}

	l := len(labels) - base
	records := stringset.New()
	defer records.Close()

	for i := 1; i <= l; i++ {
		w, found := wildcards[strings.Join(labels[i:], ".")]
		if !found || w.Answers == nil || len(w.Answers) == 0 {
			break
		}

		if i == 1 {
			insertRecordData(records, w.Answers)
		} else {
			intersectRecordData(records, w.Answers)
		}
	}

	result := WildcardTypeNone
	if records.Len() > 0 {
		result = WildcardTypeStatic
	}

	req.Ch <- result
}

func (r *Resolvers) wildcardTest(ctx context.Context, sub string) {
	var retRecords bool
	var answers []*ExtractedAnswer

	set := stringset.New()
	defer set.Close()

	// Query multiple times with unlikely names against this subdomain
	for i := 0; i < numOfWildcardTests; i++ {
		var name string

		// Generate the unlikely label / name
		for j := 0; j < 10; j++ {
			name = UnlikelyName(sub)
			if name != "" {
				break
			}
		}

		var ans []*ExtractedAnswer
		for _, t := range wildcardQueryTypes {
			msg := QueryMsg(name, t)
			ch := make(chan *dns.Msg)
			req := &resolveRequest{
				Ctx:    context.Background(),
				ID:     msg.Id,
				Name:   RemoveLastDot(msg.Question[0].Name),
				Qtype:  msg.Question[0].Qtype,
				Msg:    msg,
				Result: ch,
			}

			r.list[0].query(req)
			if resp := <-ch; resp != nil && len(resp.Answer) > 0 {
				retRecords = true
				ans = append(ans, ExtractAnswers(resp)...)
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
	// Create the slice of answers common across all the unlikely name queries
	for _, a := range answers {
		a.Data = strings.Trim(a.Data, ".")

		if set.Has(a.Data) && !already.Has(a.Data) {
			final = append(final, a)
			already.Insert(a.Data)
		}
	}

	// Determine whether the subdomain has a DNS wildcard, and if so, which type is it?
	wildcardType := WildcardTypeNone
	if retRecords {
		wildcardType = WildcardTypeStatic

		if len(final) == 0 {
			wildcardType = WildcardTypeDynamic
		}

		r.log.Printf("DNS wildcard detected: Resolver %s: %s: type: %d", r.list[0].address, "*."+sub, wildcardType)
	}

	r.wildChans.TestResult <- &testResult{
		Sub: sub,
		Result: &wildcard{
			WildcardType: wildcardType,
			Answers:      final,
			beingTested:  false,
		},
	}
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
