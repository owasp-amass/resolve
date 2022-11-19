// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestSetDetectionResolver(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	r.SetDetectionResolver(10, "8.8.8.8")
	if r.detector == nil {
		t.Errorf("failed to add the wildcard detector")
	}
}

func TestWildcardDetected(t *testing.T) {
	name := "domain.com."
	dns.HandleFunc(name, wildcardHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(100, addrstr)
	defer r.Stop()

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
			input: "jeff_foley.wildcard.domain.com",
			want:  true,
		},
		{
			label: "valid name within a wildcard",
			input: "ns.wildcard.domain.com",
			want:  false,
		},
	}

	for _, c := range cases {
		resp, err := r.QueryBlocking(context.Background(), QueryMsg(c.input, 1))
		if err != nil {
			t.Errorf("The query for %s failed %v", c.input, err)
		}
		if got := r.WildcardDetected(context.Background(), resp, "domain.com"); got != c.want {
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
