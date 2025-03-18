// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/selectors"
)

func initPool(addrstr string) (*Pool, selectors.Selector, *ConnPool) {
	var sel selectors.Selector
	timeout := 50 * time.Millisecond

	if addrstr == "" {
		sel = selectors.NewAuthoritative(timeout)
	} else {
		sel = selectors.NewRandom()
		sel.Add(NewNameserver(addrstr, timeout))
	}

	conns := NewConnPool(1, sel)
	return NewPool(0, timeout, sel, conns), sel, conns
}

func TestPoolQuery(t *testing.T) {
	dns.HandleFunc("pool.net.", typeAHandler)
	defer dns.HandleRemove("pool.net.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	num := 1000
	var failures int
	ch := make(chan *dns.Msg, num)
	defer close(ch)

	for i := 0; i < num; i++ {
		p.Query(context.Background(), QueryMsg("pool.net", dns.TypeA), ch)
	}
	for i := 0; i < num; i++ {
		if m := <-ch; m == nil || len(m.Answer) == 0 {
			failures++
		} else if rrs := AnswersByType(m, dns.TypeA); len(rrs) == 0 || (rrs[0].(*dns.A)).A.String() != "192.168.1.1" {
			failures++
		}
	}
	if failures > 50 {
		t.Errorf("too many incorrect addresses returned")
	}
}

func TestStopped(t *testing.T) {
	p, sel, conns := initPool("8.8.8.8")
	defer sel.Close()
	defer conns.Close()

	// The resolver should not be considered stopped
	select {
	case <-p.done:
		t.Errorf("resolvers should not be considered stopped")
	default:
	}

	p.Stop()
	// The resolver should be considered stopped
	select {
	case <-p.done:
	default:
		t.Errorf("resolvers should be stopped")
	}
	// It should be safe to stop the resolver pool more than once
	p.Stop()
}

func TestQuery(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	ch := make(chan *dns.Msg, 1)
	defer close(ch)

	p.Query(context.Background(), nil, ch)
	if resp := <-ch; resp != nil {
		t.Errorf("the query did not return the expected nil response message")
	}

	var success bool
	for i := 0; i < 5; i++ {
		p.Query(context.Background(), QueryMsg("caffix.net", dns.TypeA), ch)
		if m := <-ch; m != nil && len(m.Answer) > 0 {
			if rrs := AnswersByType(m, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
				success = true
				break
			}
		}
	}
	if !success {
		t.Errorf("the query did not return the expected IP address")
	}
}

func TestQueryChan(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	var success bool
	for i := 0; i < 5; i++ {
		ch := p.QueryChan(context.Background(), QueryMsg("caffix.net", dns.TypeA))
		m := <-ch
		close(ch)

		if m != nil && len(m.Answer) > 0 {
			if rrs := AnswersByType(m, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
				success = true
				break
			}
		}
	}
	if !success {
		t.Errorf("the query did not return the expected IP address")
	}
}

func TestExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	var success bool
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 5; i++ {
		if resp, err := p.Exchange(ctx, QueryMsg(name, dns.TypeA)); err == nil && resp != nil {
			if len(resp.Answer) > 0 {
				if rrs := AnswersByType(resp, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
					success = true
					break
				}
			}
		}
	}
	if !success {
		t.Errorf("the query did not return the expected IP address")
	}

	cancel()
	// The query should fail since the context has expired
	_, err = p.Exchange(ctx, QueryMsg(name, dns.TypeA))
	if err == nil {
		t.Errorf("the query did not fail as expected")
	}
}

func TestEdgeCases(t *testing.T) {
	dns.HandleFunc("google.com.", typeAHandler)
	defer dns.HandleRemove("google.com.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer sel.Close()
	defer conns.Close()
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	if _, err := p.Exchange(ctx, QueryMsg("google.com", dns.TypeA)); err == nil {
		t.Errorf("query was successful when provided an expired context")
	}

	p.Stop()
	if resp, err := p.Exchange(context.Background(), QueryMsg("google.com", dns.TypeA)); err == nil && len(resp.Answer) > 0 {
		t.Errorf("query was successful when provided a stopped Resolver")
	}
}

func TestBadWriteNextMsg(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	conns.Close()

	resp, err := p.Exchange(context.Background(), QueryMsg(name, dns.TypeA))
	if err == nil && resp.Rcode != RcodeNoResponse {
		t.Errorf("the query did not fail as expected")
	}
}

func TestTruncatedMsgs(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, truncatedHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	// Perform the query to call the TCP exchange
	_, _ = p.Exchange(context.Background(), QueryMsg(name, 1))
}
