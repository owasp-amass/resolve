// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/utils"
	"golang.org/x/time/rate"
)

func TestRegistryGet(t *testing.T) {
	r := NewRegistry(50*time.Millisecond, 0)
	defer r.Close()

	a, err := r.Get("8.8.8.8")
	if err != nil {
		t.Fatalf("Get(8.8.8.8): %v", err)
	}
	b, err := r.Get(" 8.8.8.8:53 ")
	if err != nil {
		t.Fatalf("Get(8.8.8.8:53): %v", err)
	}
	if a != b {
		t.Error("the same address with and without the default port gave two nameservers")
	}
	if c, err := r.Get("8.8.8.8:5353"); err != nil || c == a {
		t.Errorf("another port should give another nameserver: %v", err)
	}
	if _, err := r.Get("dns.google"); err == nil {
		t.Error("a host name was accepted")
	}
	if _, err := r.Get("[2001:4860:4860::8888]:53"); err != nil {
		t.Errorf("an IPv6 address was refused: %v", err)
	}
}

func TestRegistryMaxQPS(t *testing.T) {
	r := NewRegistry(50*time.Millisecond, 5)
	defer r.Close()

	before, _ := r.Get("192.0.2.1")
	if l := before.(*nameserver).rate.max.Limit(); l != 5 {
		t.Errorf("the cap is %v, want 5", l)
	}

	r.SetMaxQPS(0)
	after, _ := r.Get("192.0.2.2")
	for _, ns := range []*nameserver{before.(*nameserver), after.(*nameserver)} {
		if l := ns.rate.max.Limit(); l != rate.Inf {
			t.Errorf("the cap on %s is %v after SetMaxQPS(0), want none", ns.Address(), l)
		}
	}
	if r.MaxQPS() != 0 {
		t.Errorf("MaxQPS = %d, want 0", r.MaxQPS())
	}
}

func TestRegistryClose(t *testing.T) {
	r := NewRegistry(50*time.Millisecond, 0)
	r.Close()
	r.Close()

	if _, err := r.Get("8.8.8.8"); err == nil {
		t.Error("a closed registry handed out a nameserver")
	}
}

// TestRegistrySharedPools sends queries through two pools that share a
// registry nameserver, one of them on a bound local address, and checks that
// stopping one pool leaves the nameserver working for the other.
func TestRegistrySharedPools(t *testing.T) {
	dns.HandleFunc("shared.org.", typeAHandler)
	defer dns.HandleRemove("shared.org.")

	s, addrstr, _, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewRegistry(time.Second, 0)
	defer r.Close()

	ns, err := r.Get(addrstr)
	if err != nil {
		t.Fatalf("Get(%s): %v", addrstr, err)
	}

	sel1 := selectors.NewSharedRoundRobin(ns)
	conns1 := conn.New(2, sel1)
	p1 := pool.New(0, sel1, conns1, nil)

	sel2 := selectors.NewSharedRoundRobin(ns)
	conns2 := conn.New(2, sel2, conn.LocalAddr(netip.MustParseAddr("127.0.0.1")))
	if conns2 == nil {
		t.Fatal("conn.New could not bind to 127.0.0.1")
	}
	p2 := pool.New(0, sel2, conns2, nil)
	defer p2.Stop()
	defer sel2.Close()
	defer conns2.Close()

	for i, p := range []*pool.Pool{p1, p2} {
		resp, err := p.Exchange(context.Background(), utils.QueryMsg("shared.org", dns.TypeA))
		if err != nil || len(resp.Answer) == 0 {
			t.Errorf("pool %d: the query failed: %v", i+1, err)
		}
	}

	p1.Stop()
	sel1.Close()
	conns1.Close()

	resp, err := p2.Exchange(context.Background(), utils.QueryMsg("shared.org", dns.TypeA))
	if err != nil || len(resp.Answer) == 0 {
		t.Errorf("the shared nameserver stopped working when another pool closed: %v", err)
	}
}

// TestRegistryExpiry checks that the registry, not the shared selector, ends
// a query that goes unanswered.
func TestRegistryExpiry(t *testing.T) {
	dns.HandleFunc("expire.org.", func(dns.ResponseWriter, *dns.Msg) {})
	defer dns.HandleRemove("expire.org.")

	s, addrstr, _, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewRegistry(50*time.Millisecond, 0)
	defer r.Close()

	ns, _ := r.Get(addrstr)
	sel := selectors.NewSharedRoundRobin(ns)
	conns := conn.New(1, sel)
	p := pool.New(0, sel, conns, nil)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	if _, err := p.Exchange(ctx, utils.QueryMsg("expire.org", dns.TypeA)); err == nil {
		t.Error("an unanswered query succeeded")
	}
	if ctx.Err() != nil {
		t.Errorf("the query waited %v and was not expired by the registry", time.Since(start))
	}
}
