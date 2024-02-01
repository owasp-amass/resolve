// Copyright © by Jeff Foley 2021-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAnswersByType(t *testing.T) {
	data := []string{"192.168.1.1", "192.168.1.1", "2001:db8:0:1:1:1:1:1"}
	m := new(dns.Msg)
	m.SetReply(QueryMsg("test.caffix.net", dns.TypeA))
	m.Answer = make([]dns.RR, 3)
	m.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(data[0])}
	m.Answer[1] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(data[1])}
	m.Answer[2] = &dns.AAAA{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP(data[2])}

	ans := AnswersByType(ExtractAnswers(m), dns.TypeA)
	if l := len(ans); l != 2 {
		t.Errorf("Returned %d answers and expected %d", l, 2)
		return
	}
	if ans[0].Data != data[0] || ans[1].Data != data[1] {
		t.Errorf("First answer is %s and second was %s: expected %s and %s", ans[0].Data, ans[1].Data, data[0], data[1])
	}
}

func TestExtractAnswers(t *testing.T) {
	cases := []struct {
		label  string
		name   string
		qtype  uint16
		txt    []string
		badMsg bool
		want   string
	}{
		{
			label: "valid TypeA query",
			name:  "test.caffix.net",
			qtype: dns.TypeA,
			want:  "192.168.1.1",
		},
		{
			label: "valid TypeAAAA query",
			name:  "test.caffix.net",
			qtype: dns.TypeAAAA,
			want:  "2001:db8:0:1:1:1:1:1",
		},
		{
			label: "valid TypeCNAME query",
			name:  "test.caffix.net",
			qtype: dns.TypeCNAME,
			want:  "mail.google.com",
		},
		{
			label: "valid TypePTR query",
			name:  "192.168.1.1",
			qtype: dns.TypePTR,
			want:  "test.caffix.net",
		},
		{
			label:  "invalid TypePTR query",
			name:   "bad.address",
			qtype:  dns.TypePTR,
			badMsg: true,
		},
		{
			label: "valid TypeNS query",
			name:  "caffix.net",
			qtype: dns.TypeNS,
			want:  "ns.caffix.net",
		},
		{
			label: "valid TypeMX query",
			name:  "caffix.net",
			qtype: dns.TypeMX,
			want:  "mail.caffix.net",
		},
		{
			label: "valid TypeTXT query",
			name:  "caffix.net",
			qtype: dns.TypeTXT,
			txt:   []string{"Hello", "World"},
			want:  "Hello World",
		},
		{
			label: "valid TypeSOA query",
			name:  "caffix.net",
			qtype: dns.TypeSOA,
			want:  "ns.caffix.net,mail.caffix.net",
		},
		{
			label: "valid TypeSRV query",
			name:  "caffix.net",
			qtype: dns.TypeSRV,
			want:  "srv.google.com",
		},
	}

	for _, c := range cases {
		m := new(dns.Msg)
		if c.qtype == dns.TypePTR {
			resp := ReverseMsg(c.name)
			if c.badMsg {
				if resp != nil {
					t.Errorf("ReverseMsg should have returned nil when provided a bad address: %s", c.name)
				}
				continue
			}
			m.SetReply(resp)
		} else {
			m.SetReply(QueryMsg(c.name, c.qtype))
		}

		m.Answer = make([]dns.RR, 1)
		switch c.qtype {
		case dns.TypeA:
			m.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, A: net.ParseIP(c.want)}
		case dns.TypeAAAA:
			m.Answer[0] = &dns.AAAA{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, AAAA: net.ParseIP(c.want)}
		case dns.TypeCNAME:
			m.Answer[0] = &dns.CNAME{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Target: c.want}
		case dns.TypePTR:
			m.Answer[0] = &dns.PTR{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Ptr: c.want}
		case dns.TypeNS:
			m.Answer[0] = &dns.NS{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Ns: c.want}
		case dns.TypeMX:
			m.Answer[0] = &dns.MX{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Mx: c.want}
		case dns.TypeTXT:
			m.Answer[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Txt: c.txt}
		case dns.TypeSOA:
			parts := strings.Split(c.want, ",")
			m.Answer[0] = &dns.SOA{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Ns: parts[0], Mbox: parts[1]}
		case dns.TypeSRV:
			m.Answer[0] = &dns.SRV{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: c.qtype, Class: dns.ClassINET}, Target: c.want}
		}
		if ans := ExtractAnswers(m); len(ans) > 0 {
			if d := ans[0].Data; d != c.want {
				t.Errorf("Extracted answer for %d was %s and %s was expected", c.qtype, d, c.want)
			}
		} else {
			t.Errorf("Extracted answer for %d was empty", c.qtype)
		}
	}
}
