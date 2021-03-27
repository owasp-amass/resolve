// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPoolQuery(t *testing.T) {
	dns.HandleFunc("pool.net.", typeAHandler)
	defer dns.HandleRemove("pool.net.")

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

	pool := NewResolverPool(res, time.Second, nil, 0, nil)
	defer pool.Stop()

	ch := make(chan string, 10)
	for i := 0; i < 1000; i++ {
		go func(r Resolver, out chan string) {
			msg := QueryMsg("pool.net", 1)

			var ip string
			resp, err := r.Query(context.TODO(), msg, PriorityNormal, nil)
			if err != nil {
				out <- ip
			}

			if ans := ExtractAnswers(resp); len(ans) > 0 {
				ip = ans[0].Data
			}

			out <- ip
		}(pool, ch)
	}

	err = nil
	for i := 0; i < 1000; i++ {
		ip := <-ch

		if ip != "192.168.1.1" {
			err = errors.New("Incorrect address returned")
		}
	}

	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestPoolEdgeCases(t *testing.T) {
	dns.HandleFunc("google.com.", typeAHandler)
	defer dns.HandleRemove("google.com.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	if pool := NewResolverPool(nil, time.Second, nil, 1, nil); pool != nil {
		t.Errorf("Pool was returned when provided an empty list of Resolvers")
	}

	var res []Resolver
	for i := 0; i < 12; i++ {
		r := NewBaseResolver(addrstr, 100, nil)
		defer r.Stop()

		res = append(res, r)
	}

	baseline := NewBaseResolver(addrstr, 100, nil)
	pool := NewResolverPool(res, time.Second, baseline, 3, nil)

	if pool.Stopped() {
		t.Errorf("Pool returned an unexpected Stopped status")
	}

	pstr := "ResolverPool"
	if str := pool.String(); str != pstr {
		t.Errorf("Pool returned %s instead of the expected %s", str, pstr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if resp, err := pool.Query(ctx, QueryMsg("google.com", 1), PriorityNormal, nil); err == nil {
		if wtype := pool.WildcardType(ctx, resp, "google.com"); wtype != WildcardTypeStatic {
			t.Errorf("Pool returned an inaccurate wildcard detection status: %d", wtype)
		}
	}

	cancel()
	if _, err := pool.Query(ctx, QueryMsg("google.com", 1), PriorityNormal, nil); err == nil {
		t.Errorf("Query was successful when provided an expired context")
	}

	pool.Stop()
	if !pool.Stopped() {
		t.Errorf("Pool not stopped after being requested")
	}
}
