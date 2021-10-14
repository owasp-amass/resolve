// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolve

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestFirstProperSubdomain(t *testing.T) {
	dns.HandleFunc("first.org.", firstHandler)
	defer dns.HandleRemove("first.org.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewBaseResolver(addrstr, 10, nil)
	defer r.Stop()

	input := "one.two.sub.first.org"
	sub := FirstProperSubdomain(context.TODO(), r, input, PriorityNormal)

	expected := "sub.first.org"
	if sub != expected {
		t.Errorf("Failed to return the correct subdomain name from input %s: expected %s and got %s", input, expected, sub)
	}
}

func firstHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	if req.Question[0].Qtype != dns.TypeNS ||
		(req.Question[0].Name != "sub.first.org." && req.Question[0].Name != "first.org.") {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.NS{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Ns: "ns.first.org.",
	}
	_ = w.WriteMsg(m)
}
