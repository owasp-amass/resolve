// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPoolQuery(t *testing.T) {
	dns.HandleFunc("pool.net.", typeAHandler)
	defer dns.HandleRemove("pool.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(1000, addrstr)
	defer r.Stop()

	err = nil
	ch := make(chan *dns.Msg, 2)
	for i := 0; i < 1000; i++ {
		r.Query(context.Background(), QueryMsg("pool.net", 1), ch)
		if ans := ExtractAnswers(<-ch); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
			fmt.Println("Failed")
			err = errors.New("incorrect address returned")
		}
	}

	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestStopped(t *testing.T) {
	r := NewResolvers()
	r.AddResolvers(10, "8.8.8.8")

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
}

func TestQuery(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	defer r.Stop()

	ch := make(chan *dns.Msg, 2)
	r.Query(context.TODO(), QueryMsg("caffix.net", 1), ch)
	if ans := ExtractAnswers(<-ch); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
		t.Errorf("the query did not return the expected IP address")
	}
}

func TestQueryChan(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	defer r.Stop()

	msg := QueryMsg("caffix.net", 1)
	ch := r.QueryChan(context.TODO(), msg)
	if ans := ExtractAnswers(<-ch); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
		t.Errorf("the query did not return the expected IP address")
	}
}

func TestQueryBlocking(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	defer r.Stop()

	msg := QueryMsg("caffix.net", 1)
	resp, err := r.QueryBlocking(context.TODO(), msg)
	if err != nil {
		t.Errorf("the type A query on resolver failed: %v", err)
	}
	if ans := ExtractAnswers(resp); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
		t.Errorf("the query did not return the expected IP address")
	}
}

func TestQueryTimeout(t *testing.T) {
	dns.HandleFunc("timeout.org.", timeoutHandler)
	defer dns.HandleRemove("timeout.org.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	defer r.Stop()

	resp, err := r.QueryBlocking(context.Background(), QueryMsg("timeout.org", 1))
	if err == nil && len(ExtractAnswers(resp)) != 0 {
		t.Errorf("the query did not fail as expected")
	}
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
	time.Sleep(4000 * time.Millisecond)
	typeAHandler(w, req)
}

func runLocalUDPServer(laddr string) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// if the channel is discarded and can happen in TestShutdownUDP.
	fin := make(chan error, 2)

	go func() {
		fin <- server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), fin, nil
}

func TestEdgeCases(t *testing.T) {
	dns.HandleFunc("google.com.", typeAHandler)
	defer dns.HandleRemove("google.com.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	if _, err := r.QueryBlocking(ctx, QueryMsg("google.com", 1)); err == nil {
		t.Errorf("query was successful when provided an expired context")
	}

	r.Stop()
	if resp, err := r.QueryBlocking(context.Background(), QueryMsg("google.com", 1)); err == nil && len(ExtractAnswers(resp)) > 0 {
		t.Errorf("query was successful when provided a stopped Resolver")
	}
}
