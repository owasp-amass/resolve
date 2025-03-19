// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net"

	"github.com/miekg/dns"
)

// RemoveLastDot removes the '.' at the end of the provided FQDN.
func RemoveLastDot(name string) string {
	sz := len(name)
	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}

// QueryMsg generates a message used for a forward DNS query.
func QueryMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Extra = append(m.Extra, SetupOptions())
	return m
}

// ReverseMsg generates a message used for a reverse DNS query.
func ReverseMsg(addr string) *dns.Msg {
	if net.ParseIP(addr) != nil {
		if r, err := dns.ReverseAddr(addr); err == nil {
			return QueryMsg(r, dns.TypePTR)
		}
	}
	return nil
}

// WalkMsg generates a message used for a NSEC walk query.
func WalkMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(dns.DefaultMsgSize, true)
	return m
}

// SetupOptions returns the EDNS0_SUBNET option for hiding our location.
func SetupOptions() *dns.OPT {
	return &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  dns.DefaultMsgSize,
		},
		Option: []dns.EDNS0{&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 0,
			SourceScope:   0,
			Address:       net.ParseIP("0.0.0.0").To4(),
		}},
	}
}

// AnswersByType returns only the answers from the DNS Answer section matching the provided type.
func AnswersByType(msg *dns.Msg, qtype uint16) []dns.RR {
	var subset []dns.RR

	if len(msg.Answer) == 0 {
		return subset
	}

	for _, a := range msg.Answer {
		if a.Header().Rrtype == qtype {
			subset = append(subset, a)
		}
	}

	return subset
}
