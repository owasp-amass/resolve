// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestInitializeResolver(t *testing.T) {
	r := NewResolvers()

	if res := r.initializeResolver("192.168.1.1"); res == nil ||
		res.address.IP.String() != "192.168.1.1" || res.address.Port != 53 {
		t.Errorf("failed to add the port to the provided address")
	}
	if res := r.initializeResolver("300.300.300.300"); res != nil {
		t.Errorf("failed to detect the invalid IP address provided")
	}
}

func TestSetTimeout(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers("8.8.8.8")
	defer r.Stop()

	timeout := 2 * time.Second
	r.SetTimeout(timeout)

	if r.timeout != timeout || r.pool.GetResolver("caffix.net").xchgs.timeout != timeout {
		t.Errorf("failed to set the new timeout value throughout the resolver pool")
	}
}

func TestPoolQuery(t *testing.T) {
	dns.HandleFunc("pool.net.", typeAHandler)
	defer dns.HandleRemove("pool.net.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()

	num := 1000
	var failures int
	ch := make(chan *dns.Msg, num)
	for i := 0; i < num; i++ {
		r.Query(context.Background(), QueryMsg("pool.net", 1), ch)
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

func TestLen(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()
	// Test that the length is zero before adding DNS resolvers
	if r.Len() > 0 {
		t.Errorf("the length was greater than zero before adding DNS resolvers")
	}
	// Test that the length equals one after adding a single resolver
	_ = r.AddResolvers("8.8.8.8")
	if r.Len() != 1 {
		t.Errorf("the length did not equal one after adding the first resolver")
	}
}

func TestAddLogger(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	r.SetLogger(nil)
	if r.log != nil {
		t.Errorf("failed to set the resolver pool logger")
	}
}

func TestAddResolvers(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()
	// Test that the resolver is added with a QPS greater than zero
	if err := r.AddResolvers("8.8.8.8"); err != nil || r.Len() == 0 {
		t.Errorf("the resolver was not added with a QPS greater than zero")
	}
}

func TestStopped(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers("8.8.8.8")

	// The resolver should not be considered stopped
	select {
	case <-r.done:
		t.Errorf("resolvers should not be considered stopped")
	default:
	}

	r.Stop()
	// The resolver should be considered stopped
	select {
	case <-r.done:
	default:
		t.Errorf("resolvers should be stopped")
	}
	// It should be safe to stop the resolver pool more than once
	r.Stop()
}

func TestQuery(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	r.SetDetectionResolver("8.8.4.4")

	ch := make(chan *dns.Msg, 1)
	r.Query(context.Background(), nil, ch)
	if resp := <-ch; resp != nil {
		t.Errorf("the query did not return the expected nil response message")
	}

	var success bool
	for i := 0; i < 5; i++ {
		r.Query(context.Background(), QueryMsg("caffix.net", 1), ch)
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

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()

	var success bool
	for i := 0; i < 5; i++ {
		ch := r.QueryChan(context.Background(), QueryMsg("caffix.net", 1))
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

func TestQueryBlocking(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()

	var success bool
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 5; i++ {
		if resp, err := r.QueryBlocking(ctx, QueryMsg(name, 1)); err == nil && resp != nil {
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
	_, err = r.QueryBlocking(ctx, QueryMsg(name, 1))
	if err == nil {
		t.Errorf("the query did not fail as expected")
	}
}

func TestEnforceMaxQPS(t *testing.T) {
	r := NewResolvers()
	r.SetMaxQPS(20)
	// The query should fail since no DNS resolver has been added to the pool
	resp, _ := r.QueryBlocking(context.Background(), QueryMsg("caffix.net", 1))
	if resp.Rcode != RcodeNoResponse {
		t.Errorf("the query did not fail as expected")
	}
}

func TestQueryTimeout(t *testing.T) {
	dns.HandleFunc("timeout.org.", timeoutHandler)
	defer dns.HandleRemove("timeout.org.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()

	resp, err := r.QueryBlocking(context.Background(), QueryMsg("timeout.org", 1))
	if err == nil && len(resp.Answer) > 0 {
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

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	if _, err := r.QueryBlocking(ctx, QueryMsg("google.com", 1)); err == nil {
		t.Errorf("query was successful when provided an expired context")
	}

	r.Stop()
	if resp, err := r.QueryBlocking(context.Background(), QueryMsg("google.com", 1)); err == nil && len(resp.Answer) > 0 {
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

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	r.conns.Close()

	resp, err := r.QueryBlocking(context.Background(), QueryMsg(name, 1))
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

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()

	// Perform the query to call the TCP exchange
	_, _ = r.QueryBlocking(context.Background(), QueryMsg(name, 1))
}

func TestTCPExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalTCPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	res := r.pool.GetResolver(name)

	ch := make(chan *dns.Msg, 2)
	msg := QueryMsg(name, 1)
	res.tcpExchange(&request{
		Res:    res,
		Msg:    msg,
		Result: ch,
	})

	if resp := <-ch; resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		if len(resp.Answer) > 0 {
			if rrs := AnswersByType(resp, dns.TypeA); len(rrs) == 0 || (rrs[0].(*dns.A)).A.String() != "192.168.1.1" {
				t.Errorf("the query did not return the expected IP address")
			}
		}
	} else {
		t.Errorf("The TCP exchange process failed to handle the query for: %s", name)
	}
}

func TestBadTCPExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	res := r.pool.GetResolver(name)

	ch := make(chan *dns.Msg, 2)
	msg := QueryMsg(name, 1)
	res.tcpExchange(&request{
		Res:    res,
		Msg:    msg,
		Result: ch,
	})

	if resp := <-ch; resp.Rcode != RcodeNoResponse {
		t.Errorf("The TCP exchange process did not fail as expected")
	}
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

func timeoutHandler(w dns.ResponseWriter, req *dns.Msg) {
	time.Sleep(DefaultTimeout + time.Second)
	typeAHandler(w, req)
}

func RunLocalUDPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return RunLocalServer(pc, nil, opts...)
}

func RunLocalTCPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return RunLocalServer(nil, l, opts...)
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
