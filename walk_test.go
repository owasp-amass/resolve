// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"testing"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

var nsecLinkedList []string = []string{
	"0.walk.com.",
	"16a.walk.com.",
	"16aaaa.walk.com.",
	"16dual.walk.com.",
	"32a.walk.com.",
	"32aaaa.walk.com.",
	"32aaaa-long.walk.com.",
	"32dual.walk.com.",
	"32dual-long.walk.com.",
	"64a.walk.com.",
	"64aaaa.walk.com.",
	"64dual.walk.com.",
	"_openpgpkey.walk.com.",
	"_tcp.walk.com.",
	"_tls.walk.com.",
	"_udp.walk.com.",
	"a.walk.com.",
	"aaaa.walk.com.",
	"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.walk.com.",
	"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890.walk.com.",
	"cname.walk.com.",
	"cname1.walk.com.",
	"cname2.walk.com.",
	"cname3.walk.com.",
	"cname4.walk.com.",
	"cnamefinal.walk.com.",
	"cnamex.walk.com.",
	"cnamey.walk.com.",
	"cnamez.walk.com.",
	"darm.walk.com.",
	"dyn.walk.com.",
	"fdorf.walk.com.",
	"fdorf-kessler.walk.com.",
	"fdorf-wnuk.walk.com.",
	"fg.walk.com.",
	"foobar.walk.com.",
	"gezkgjhasxalp4h31yv8.walk.com.",
	"host-dane.walk.com.",
	"host-dane-self.walk.com.",
	"host-dnssec.walk.com.",
	"ib.walk.com.",
	"ib-unsigned.walk.com.",
	"ib1.walk.com.",
	"ib2.walk.com.",
	"ib3-report.walk.com.",
	"ib4-recursive.walk.com.",
	"ip.walk.com.",
	"ip-documentation.walk.com.",
	"ipv4-doc.walk.com.",
	"ipv4-documentation.walk.com.",
	"ipv6-doc.walk.com.",
	"ipv6-documentation.walk.com.",
	"johannes.walk.com.",
	"loop.walk.com.",
	"mail.walk.com.",
	"many-rrs.walk.com.",
	"nicolai30.walk.com.",
	"ns0.walk.com.",
	"ns1.walk.com.",
	"ns1-v4.walk.com.",
	"ns1-v6.walk.com.",
	"ns2.walk.com.",
	"pa.walk.com.",
	"pool.walk.com.",
	"strom.walk.com.",
	"sub1.walk.com.",
	"test.walk.com.",
	"tr18.walk.com.",
	"ttl-0s.walk.com.",
	"ttl-1m.walk.com.",
	"ttl-1s.walk.com.",
	"ttl-30d.walk.com.",
	"ttl-52w.walk.com.",
	"ttl-max.walk.com.",
	"txt.walk.com.",
	"viola.walk.com.",
	"www.walk.com.",
	"xn--0cabeeefjijjmm4zxa8aa0byb0b1b6b5byc5b0cycxc6czc5c4c.walk.com.",
	"xn--bergrssentrger-gib5zmd.walk.com.",
	"xn--ddabeekggjjjx59c0ay7a7a9dtb0a6a6b4b7f2bxcwc1e0cvc8c7c.walk.com.",
	"xn--dsire-bsad.walk.com.",
	"xn--fan-2na.walk.com.",
	"xn--fnf-hoa.walk.com.",
	"xn--heizlrckstossabdmpfung-g5b33b6e.walk.com.",
	"xn--hr-yia.walk.com.",
	"xn--ser-0ma.walk.com.",
	"xn--ss-xja9aehhiki25gyaz3a4a6a7a3bzb4b8b5b3bzcxczc1c1c2ewc3c.walk.com.",
	"xn--yourt-l1a.walk.com.",
	"walk.com.",
}

func TestNsecTraversal(t *testing.T) {
	name := "walk.com."
	dns.HandleFunc(name, walkHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(addrstr)

	ctx, cancel := context.WithCancel(context.Background())
	names, err := r.NsecTraversal(ctx, "walk.com")
	if err != nil {
		t.Errorf("The NSEC traversal was not successful: %v", err)
	}

	set := stringset.New()
	defer set.Close()

	for _, name := range names {
		set.Insert(name.NextDomain)
	}

	nsecSet := stringset.New(nsecLinkedList...)
	defer nsecSet.Close()

	nsecSet.Subtract(set)
	if nsecSet.Len() != 0 {
		t.Errorf("The NSEC traversal found %d names and failed to discover the following names: %v", set.Len(), nsecSet.Slice())
	}

	cancel()
	if _, err := r.NsecTraversal(ctx, "walk.com"); err == nil {
		t.Errorf("The NSEC traversal failed to return an error with an expired context")
	}

	r.Stop()
	if _, err := r.NsecTraversal(context.Background(), "walk.com"); err == nil {
		t.Errorf("The NSEC traversal failed to return an error with a stopped resolver pool")
	}
}

func TestBadNsecTraversal(t *testing.T) {
	name := "walk.com."
	dns.HandleFunc(name, noNSECHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	defer r.Stop()
	_ = r.AddResolvers(addrstr)

	if _, err := r.NsecTraversal(context.Background(), "walk.com"); err == nil {
		t.Errorf("The NSEC traversal failed to return an error when the NSEC record was absent")
	}
}

func noNSECHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	m.Rcode = dns.RcodeSuccess
	_ = w.WriteMsg(m)
}

func walkHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	if req.Question[0].Qtype != dns.TypeNSEC {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}

	name := "walk.com."
	next := nsecLinkedList[0]

	if req.Question[0].Name != name {
		l := len(nsecLinkedList) - 1
		for i := 0; i < l; i++ {

			if req.Question[0].Name == nsecLinkedList[i] {
				name = nsecLinkedList[i]
				next = nsecLinkedList[i+1]
				break
			}
		}
	}

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		NextDomain: next,
	}
	_ = w.WriteMsg(m)
}
