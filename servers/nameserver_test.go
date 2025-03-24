// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

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
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

func initPool(addrstr string) (*pool.Pool, types.Selector, types.Conn) {
	var sel types.Selector
	timeout := 50 * time.Millisecond

	if addrstr == "" {
		sel = selectors.NewAuthoritative(timeout, NewNameserver)
	} else {
		sel = selectors.NewSingle(timeout, NewNameserver(addrstr))
	}

	conns := conn.New(runtime.NumCPU(), sel)
	return pool.New(0, sel, conns, nil), sel, conns
}

func TestNewNameserver(t *testing.T) {
	if ns := newNameserver("192.168.1.1"); ns == nil ||
		ns.Address().IP.String() != "192.168.1.1" || ns.Address().Port != 53 {
		t.Errorf("failed to add the port to the provided address")
	}
	if ns := newNameserver("300.300.300.300"); ns != nil &&
		ns.Address().IP.String() == "300.300.300.300" {
		t.Errorf("failed to detect the invalid IP address provided")
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

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()

	resp, err := p.Exchange(context.Background(), utils.QueryMsg("timeout.org", dns.TypeA))
	if err == nil && len(resp.Answer) > 0 {
		t.Errorf("the query did not fail as expected")
	}
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

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()
	serv := p.Selector.Get(name)

	ch := make(chan *dns.Msg, 1)
	defer close(ch)
	msg := utils.QueryMsg(name, dns.TypeA)

	req := types.NewRequest(msg, ch)
	req.SetServer(serv)
	utils.TCPExchange(req, 50*time.Millisecond)

	if resp := <-ch; resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		if len(resp.Answer) > 0 {
			if rrs := utils.AnswersByType(resp, dns.TypeA); len(rrs) == 0 || (rrs[0].(*dns.A)).A.String() != "192.168.1.1" {
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

	p, sel, conns := initPool(addrstr)
	defer p.Stop()
	defer sel.Close()
	defer conns.Close()
	serv := p.Selector.Get(name)

	ch := make(chan *dns.Msg, 1)
	defer close(ch)
	msg := utils.QueryMsg(name, dns.TypeA)

	req := types.NewRequest(msg, ch)
	req.SetServer(serv)
	utils.TCPExchange(req, 50*time.Millisecond)

	if resp := <-ch; resp.Rcode != types.RcodeNoResponse {
		t.Errorf("The TCP exchange process did not fail as expected")
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
	time.Sleep(types.DefaultTimeout + time.Second)
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
