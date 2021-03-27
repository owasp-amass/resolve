// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestWildcardType(t *testing.T) {
	dns.HandleFunc("domain.com.", wildcardHandler)
	defer dns.HandleRemove("domain.com.")

	s, addrstr, _, err := runLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer s.Shutdown()

	r := NewBaseResolver(addrstr, 100, nil)
	defer r.Stop()

	cases := []struct {
		label string
		input string
		want  int
	}{
		{
			label: "valid name outside of a wildcard",
			input: "www.domain.com",
			want:  WildcardTypeNone,
		},
		{
			label: "invalid name within a wildcard",
			input: "jeff_foley.wildcard.domain.com",
			want:  WildcardTypeStatic,
		},
		{
			label: "valid name within a wildcard",
			input: "ns.wildcard.domain.com",
			want:  WildcardTypeNone,
		},
	}

	for _, c := range cases {
		msg := QueryMsg(c.input, 1)

		resp, err := r.Query(context.TODO(), msg, PriorityNormal, nil)
		if err != nil {
			t.Errorf("The query for %s failed %v", c.input, err)
		}
		if got := r.WildcardType(context.TODO(), resp, "domain.com"); got != c.want {
			t.Errorf("Wildcard detection for %s returned %d instead of the expected %d", c.input, got, c.want)
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
		w.WriteMsg(m)
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
	w.WriteMsg(m)
}
