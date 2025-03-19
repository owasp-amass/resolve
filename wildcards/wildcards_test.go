// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wildcards

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/utils"
)

func TestWildcardDetected(t *testing.T) {
	name := "domain.com."
	dns.HandleFunc(name, wildcardHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	timeout := 50 * time.Millisecond
	sel := selectors.NewRandom()
	serv := servers.NewNameserver(addrstr, timeout)
	sel.Add(serv)
	conns := conn.New(1, sel.Lookup)
	detector := NewDetector(serv, conns, nil)
	p := pool.New(0, sel, conns, nil)
	defer p.Stop()
	defer serv.Stop()
	defer sel.Close()
	defer conns.Close()

	cases := []struct {
		label string
		input string
		want  bool
	}{
		{
			label: "valid name outside of a wildcard",
			input: "www.domain.com",
			want:  false,
		},
		{
			label: "invalid name within a wildcard",
			input: "foley.wildcard.domain.com",
			want:  true,
		},
		{
			label: "valid name within a wildcard",
			input: "ns.wildcard.domain.com",
			want:  false,
		},
	}

	for _, c := range cases {
		resp, err := p.Exchange(context.Background(), utils.QueryMsg(c.input, 1))
		if err != nil {
			t.Errorf("The query for %s failed %v", c.input, err)
			continue
		}
		if got := detector.WildcardDetected(context.Background(), resp, "domain.com"); got != c.want {
			t.Errorf("Wildcard detection for %s returned %t instead of the expected %t", c.input, got, c.want)
		}
	}
}

func wildcardHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	var addr string
	if name := req.Question[0].Name; name == "www.domain.com." {
		addr = "192.168.1.14"
	} else if name == "ns.wildcard.domain.com." {
		addr = "192.168.1.2"
	} else if strings.HasSuffix(name, ".wildcard.domain.com.") {
		addr = "192.168.1.64"
	}

	if addr == "" {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP(addr),
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
