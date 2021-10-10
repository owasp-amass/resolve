// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolve

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStopped(t *testing.T) {
	r := NewBaseResolver("8.8.8.8", 10, nil)

	// The resolver should not be considered stopped
	if r.Stopped() {
		t.Errorf("Resolver %s should not be considered stopped", r)
	}

	r.Stop()
	// The resolver should be considered stopped
	if !r.Stopped() {
		t.Errorf("Resolver %s should be stopped", r)
	}
}

func TestQuery(t *testing.T) {
	dns.HandleFunc("caffix.net.", typeAHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	r := NewBaseResolver(addrstr, 10, nil)
	defer r.Stop()

	msg := QueryMsg("caffix.net", 1)
	resp, err := r.Query(context.TODO(), msg, PriorityNormal, nil)
	if err != nil {
		t.Errorf("The type A query on resolver %s failed: %v", r, err)
	}

	if ans := ExtractAnswers(resp); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
		t.Errorf("The query did not return the expected IP address")
	}
}

func TestQueryTimeout(t *testing.T) {
	dns.HandleFunc("timeout.org.", timeoutHandler)
	defer dns.HandleRemove("timeout.org.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	r := NewBaseResolver(addrstr, 10, nil)
	defer r.Stop()

	msg := QueryMsg("timeout.org", 1)
	_, err = r.Query(context.TODO(), msg, PriorityNormal, nil)
	if err == nil {
		t.Errorf("The query did not fail as expected")
	}
	if e, ok := err.(*ResolveError); ok && e.Rcode != TimeoutRcode {
		t.Errorf("The query did not return the correct error code")
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
	w.WriteMsg(m)
}

func timeoutHandler(w dns.ResponseWriter, req *dns.Msg) {
	time.Sleep(2500 * time.Millisecond)
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
	fin := make(chan error, 1)

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
	defer s.Shutdown()

	if r := NewBaseResolver(addrstr, 0, nil); r != nil {
		t.Errorf("resolver was returned when provided an invalid number of messages per second argument")
	}

	r := NewBaseResolver(addrstr, 10, nil)
	ctx, cancel := context.WithCancel(context.Background())

	for _, priority := range []int{PriorityLow - 1, PriorityCritical + 1} {
		if _, err := r.Query(ctx, QueryMsg("google.com", 1), -1, nil); err == nil {
			t.Errorf("resolver was returned with an invalid priority of %d", priority)
		}
	}

	cancel()
	if _, err := r.Query(ctx, QueryMsg("google.com", 1), PriorityNormal, nil); err == nil {
		t.Errorf("query was successful when provided an expired context")
	}

	r.Stop()
	if _, err := r.Query(ctx, QueryMsg("google.com", 1), PriorityNormal, nil); err == nil {
		t.Errorf("query was successful when provided a stopped Resolver")
	}
}
