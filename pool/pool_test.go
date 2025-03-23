// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

func initPool(addrstr string) (*Pool, types.Selector, types.Conn) {
	var sel types.Selector
	timeout := 50 * time.Millisecond

	if addrstr == "" {
		sel = selectors.NewAuthoritative(timeout, servers.NewNameserver)
	} else {
		sel = selectors.NewSingle(timeout, servers.NewNameserver(addrstr))
	}

	conns := conn.New(runtime.NumCPU(), sel)
	return New(0, sel, conns, nil), sel, conns
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

	num := 100
	var failures int
	ch := make(chan *dns.Msg, 50)
	defer close(ch)

	for i := 0; i < num; i++ {
		p.Query(context.Background(), utils.QueryMsg("pool.net", dns.TypeA), ch)
	}
	for i := 0; i < num; i++ {
		if m := <-ch; m == nil || len(m.Answer) == 0 {
			failures++
		} else if rrs := utils.AnswersByType(m, dns.TypeA); len(rrs) == 0 || (rrs[0].(*dns.A)).A.String() != "192.168.1.1" {
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
		p.Query(context.Background(), utils.QueryMsg("caffix.net", dns.TypeA), ch)
		if m := <-ch; m != nil && len(m.Answer) > 0 {
			if rrs := utils.AnswersByType(m, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
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
		ch := p.QueryChan(context.Background(), utils.QueryMsg("caffix.net", dns.TypeA))
		m := <-ch
		close(ch)

		if m != nil && len(m.Answer) > 0 {
			if rrs := utils.AnswersByType(m, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
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
		if resp, err := p.Exchange(ctx, utils.QueryMsg(name, dns.TypeA)); err == nil && resp != nil {
			if len(resp.Answer) > 0 {
				if rrs := utils.AnswersByType(resp, dns.TypeA); len(rrs) > 0 && (rrs[0].(*dns.A)).A.String() == "192.168.1.1" {
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
	_, err = p.Exchange(ctx, utils.QueryMsg(name, dns.TypeA))
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
	if _, err := p.Exchange(ctx, utils.QueryMsg("google.com", dns.TypeA)); err == nil {
		t.Errorf("query was successful when provided an expired context")
	}

	p.Stop()
	if resp, err := p.Exchange(context.Background(), utils.QueryMsg("google.com", dns.TypeA)); err == nil && len(resp.Answer) > 0 {
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

	resp, err := p.Exchange(context.Background(), utils.QueryMsg(name, dns.TypeA))
	if err == nil && resp.Rcode != types.RcodeNoResponse {
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
	_, _ = p.Exchange(context.Background(), utils.QueryMsg(name, 1))
}

func typeAHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("192.168.1.1"),
	}
	_ = w.WriteMsg(m)
}

func truncatedHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	m.Truncated = true
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("192.168.1.1"),
	}
	_ = w.WriteMsg(m)
}

func RunLocalUDPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return RunLocalServer(pc, nil, opts...)
}

func RunLocalServer(pc net.PacketConn, l net.Listener, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	server := &dns.Server{
		PacketConn: pc,
		Listener:   l,

		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	for _, opt := range opts {
		opt(server)
	}

	var (
		addr   string
		closer io.Closer
	)
	if l != nil {
		addr = l.Addr().String()
		closer = l
	} else {
		addr = pc.LocalAddr().String()
		closer = pc
	}
	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// if the channel is discarded and can happen in TestShutdownUDP.
	fin := make(chan error, 1)

	go func() {
		fin <- server.ActivateAndServe()
		closer.Close()
	}()

	waitLock.Lock()
	return server, addr, fin, nil
}
