// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

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
	// Test for TypeA messages
	qtype := dns.TypeA
	data := "192.168.1.1"
	m := new(dns.Msg)
	m.SetReply(QueryMsg("test.caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, A: net.ParseIP(data)}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeAAAA messages
	qtype = dns.TypeAAAA
	data = "2001:db8:0:1:1:1:1:1"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("test.caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.AAAA{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, AAAA: net.ParseIP(data)}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeCNAME messages
	qtype = dns.TypeCNAME
	data = "mail.google.com"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("test.caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.CNAME{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Target: data}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypePTR messages
	qtype = dns.TypePTR
	data = "test.caffix.net"
	m = new(dns.Msg)
	m.SetReply(ReverseMsg("192.168.1.1"))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.PTR{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Ptr: data}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeNS messages
	qtype = dns.TypeNS
	data = "ns.caffix.net"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.NS{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Ns: data}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeMX messages
	qtype = dns.TypeMX
	data = "mail.caffix.net"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.MX{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Mx: data}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeTXT messages
	qtype = dns.TypeTXT
	datas := []string{"Hello", "World"}
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Txt: datas}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		j := strings.Join(datas, " ")

		if d := ans[0].Data; d != j {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, j)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeSOA messages
	qtype = dns.TypeSOA
	data = "ns.caffix.net,mail.caffix.net"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.SOA{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET},
		Ns: "ns.caffix.net", Mbox: "mail.caffix.net"}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeSPF messages
	qtype = dns.TypeSPF
	data = "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.SPF{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Txt: []string{data}}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
	// Test for TypeSRV messages
	qtype = dns.TypeSRV
	data = "srv.google.com"
	m = new(dns.Msg)
	m.SetReply(QueryMsg("caffix.net", qtype))
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.SRV{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET}, Target: data}
	if ans := ExtractAnswers(m); len(ans) > 0 {
		if d := ans[0].Data; d != data {
			t.Errorf("Extracted answer for %d was %s and %s was expected", qtype, d, data)
		}
	} else {
		t.Errorf("Extracted answer for %d was empty", qtype)
	}
}
