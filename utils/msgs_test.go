// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net"
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

	ans := AnswersByType(m, dns.TypeA)
	if l := len(ans); l != 2 {
		t.Errorf("Returned %d answers and expected %d", l, 2)
		return
	}
}
