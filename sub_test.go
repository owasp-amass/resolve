// Copyright © by Jeff Foley 2021-2022. All rights reserved.
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

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	r.AddResolvers(10, addrstr)
	defer r.Stop()

	input := "one.two.sub.first.org"
	sub := FirstProperSubdomain(context.TODO(), r, input)

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
