// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRetryQuery(t *testing.T) {
	dns.HandleFunc("retry.net.", retryHandler)
	defer dns.HandleRemove("retry.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	r := NewBaseResolver(addrstr, 100, nil)
	defer r.Stop()

	max := 20
	var count int
	msg := QueryMsg("retry.net", 1)
	if _, err := r.Query(context.TODO(), msg, PriorityNormal, func(times, priority int, m *dns.Msg) bool {
		var retry bool

		count++
		if count < max {
			retry = true
		}

		return retry
	}); err == nil || count != max {
		t.Errorf("The number of retries is %d instead of %d", count, max)
	}
}

func TestDefaultRetryPolicy(t *testing.T) {
	dns.HandleFunc("retry.net.", retryHandler)
	defer dns.HandleRemove("retry.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	var res []Resolver
	for i := 0; i < 10; i++ {
		r := NewBaseResolver(addrstr, 100, nil)
		defer r.Stop()

		res = append(res, r)
	}

	pool := NewResolverPool(res, time.Second, nil, 1, nil)
	defer pool.Stop()

	priorities := []int{PriorityLow, PriorityNormal, PriorityHigh, PriorityCritical}
	attempts := []int{AttemptsPriorityLow, AttemptsPriorityNormal, AttemptsPriorityHigh, AttemptsPriorityCritical}
	for i, p := range priorities {
		msg := QueryMsg("retry.net", 1)

		var count int
		att := attempts[i] + 1
		if _, err := pool.Query(context.TODO(), msg, p, func(times, priority int, m *dns.Msg) bool {
			count++
			return PoolRetryPolicy(times, priority, m)
		}); err == nil || count != att {
			t.Errorf("The number of retries is %d instead of %d", count, att)
		}
	}
}

func retryHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeNotImplemented
	w.WriteMsg(m)
}
