// Copyright © by Jeff Foley 2022-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve"
)

var resolvers = []string{
	"8.8.8.8",        // Google
	"1.1.1.1",        // Cloudflare
	"9.9.9.9",        // Quad9
	"208.67.222.222", // Cisco OpenDNS
	"84.200.69.80",   // DNS.WATCH
	"64.6.64.6",      // Neustar DNS
	"8.26.56.26",     // Comodo Secure DNS
	"205.171.3.65",   // Level3
	"134.195.4.2",    // OpenNIC
	"185.228.168.9",  // CleanBrowsing
	"76.76.19.19",    // Alternate DNS
	"37.235.1.177",   // FreeDNS
	"77.88.8.1",      // Yandex.DNS
	"94.140.14.140",  // AdGuard
	"38.132.106.139", // CyberGhost
	"74.82.42.42",    // Hurricane Electric
	"76.76.2.0",      // ControlD
}

// CommaSep implements the flag.Value interface.
type CommaSep []string

// String implements the fmt.Stringer interface.
func (c CommaSep) String() string {
	if len(c) == 0 {
		return ""
	}
	return strings.Join(c, ",")
}

// Set implements the flag.Value interface.
func (c *CommaSep) Set(s string) error {
	if s == "" {
		return fmt.Errorf("failed to parse the provided string: %s", s)
	}

	strs := strings.Split(s, ",")
	for _, s := range strs {
		if s != "" {
			*c = append(*c, strings.TrimSpace(s))
		}
	}
	return nil
}

func ResolverFileList(p string) []string {
	set := stringset.New()
	defer set.Close()

	if input, err := os.Open(p); err == nil {
		defer input.Close()

		if err := ExtractLines(input, func(str string) error {
			set.Insert(str)
			return nil
		}); err == nil {
			return set.Slice()
		}
	}

	set.InsertMany(resolvers...)
	return set.Slice()
}

func InputDomainNames(input io.Reader, requests chan string) {
	_ = ExtractLines(input, func(str string) error {
		name := resolve.RemoveLastDot(strings.ToLower(str))

		if _, ok := dns.IsDomainName(name); ok {
			requests <- name
		}
		return nil
	})
}

func ExtractLines(reader io.Reader, cb func(str string) error) error {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		if err := cb(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func StringsToQtypes(strs []string) []uint16 {
	var qtypes []uint16

	for _, str := range strs {
		if qtype := StringToQtype(str); qtype != dns.TypeNone {
			qtypes = append(qtypes, qtype)
		}
	}
	return qtypes
}

func StringToQtype(str string) uint16 {
	switch str {
	case "A":
		return dns.TypeA
	case "NS":
		return dns.TypeNS
	case "CNAME":
		return dns.TypeCNAME
	case "SOA":
		return dns.TypeSOA
	case "PTR":
		return dns.TypePTR
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "AAAA":
		return dns.TypeAAAA
	}
	return dns.TypeNone
}
