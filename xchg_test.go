// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	res := r.servers.AllResolvers()[0]

	ch := make(chan *dns.Msg, 2)
	msg := QueryMsg(name, 1)
	res.exchange(&request{
		Ctx:    context.Background(),
		ID:     msg.Id,
		Name:   RemoveLastDot(msg.Question[0].Name),
		Qtype:  msg.Question[0].Qtype,
		Msg:    msg,
		Result: ch,
	})

	if resp := <-ch; resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		if ans := ExtractAnswers(resp); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
			t.Errorf("the query did not return the expected IP address")
		}
	} else {
		t.Errorf("The UDP exchange process failed to handle the query for: %s", name)
	}
}

func TestTCPExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	res := r.servers.AllResolvers()[0]

	msg := QueryMsg(name, 1)
	resp, _, err := res.xchg(&request{
		Ctx:   context.Background(),
		ID:    msg.Id,
		Name:  RemoveLastDot(msg.Question[0].Name),
		Qtype: msg.Question[0].Qtype,
		Msg:   msg,
	}, "tcp")

	if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		if ans := ExtractAnswers(resp); len(ans) == 0 || ans[0].Data != "192.168.1.1" {
			t.Errorf("the query did not return the expected IP address")
		}
	} else {
		t.Errorf("The TCP exchange process failed to handle the query for: %s", name)
	}
}

func TestBadTCPExchange(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)
	defer r.Stop()
	res := r.servers.AllResolvers()[0]

	msg := QueryMsg(name, 1)
	resp, _, err := res.xchg(&request{
		Ctx:   context.Background(),
		ID:    msg.Id,
		Name:  RemoveLastDot(msg.Question[0].Name),
		Qtype: msg.Question[0].Qtype,
		Msg:   msg,
	}, "tcp")

	if err == nil && resp.Rcode != RcodeNoResponse {
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
