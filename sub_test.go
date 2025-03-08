// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestFirstProperSubdomain(t *testing.T) {
	dns.HandleFunc("first.org.", firstHandler)
	defer dns.HandleRemove("first.org.")

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(10, addrstr)
	defer r.Stop()

	expected := "sub.first.org"
	input := "one.two.sub.first.org"
	if sub := FirstProperSubdomain(context.Background(), r, input); sub != expected {
		t.Errorf("Failed to return the correct subdomain name from input %s: expected %s and got %s", input, expected, sub)
	}
}

func firstHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	if req.Question[0].Qtype != dns.TypeNS {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	switch req.Question[0].Name {
	case "first.org.", "sub.first.org.":
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
	case "two.sub.first.org.":
		m.Rcode = dns.RcodeSuccess
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}
