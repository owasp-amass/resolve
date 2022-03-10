// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

func TestCommaSep(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label:    "Empty input",
			input:    "",
			expected: "",
		}, {
			label:    "Valid input",
			input:    "CNAME,A,AAAA",
			ok:       true,
			expected: "CNAME,A,AAAA",
		}, {
			label:    "Extra comma",
			input:    "CNAME,A,AAAA,",
			ok:       true,
			expected: "CNAME,A,AAAA",
		}, {
			label:    "With whitespace",
			input:    "CNAME  , A ,\tAAAA",
			ok:       true,
			expected: "CNAME,A,AAAA",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			var qtypes CommaSep

			if err := qtypes.Set(c.input); (err == nil) == c.ok {
				if got := qtypes.String(); got != c.expected {
					t.Errorf("Got: %s; Expected: %s", got, c.expected)
				}
			} else {
				t.Errorf("Set did not return the expected error value: %v", err)
			}
		}
		t.Run(c.label, f)
	}
}

func TestResolverList(t *testing.T) {
	set := stringset.New(resolvers...)
	defer set.Close()

	for _, p := range []string{"", "../../example/resolvers.txt"} {
		list := stringset.New(ResolverFileList(p)...)
		defer list.Close()

		list.Intersect(set)
		if list.Len() != set.Len() {
			t.Errorf("Failed to obtain all of the DNS resolvers from %s", p)
		}
	}
}

func TestInputDomainNames(t *testing.T) {
	results := make(chan string, 2)
	names := []string{"www.caffix.net", "mail.caffix.net", "ftp.caffix.net"}
	reader := strings.NewReader(names[0] + "\n" + names[1] + "\n" + names[2])

	go InputDomainNames(reader, results)
	for _, name := range names {
		if n := <-results; n != name {
			t.Errorf("Got: %s; Expected: %q", n, name)
		}
	}
}

func TestExtractLines(t *testing.T) {
	names := []string{"www.caffix.net", "mail.caffix.net", "ftp.caffix.net"}
	reader := strings.NewReader(names[0] + "\n" + names[1] + "\n" + names[2])
	set := stringset.New(names...)
	defer set.Close()

	err := ExtractLines(reader, func(str string) error {
		set.Remove(str)
		return nil
	})
	if err != nil || set.Len() > 0 {
		t.Errorf("Failed to extract all names from the reader: %s", set.String())
	}

	second := strings.NewReader("test")
	if err := ExtractLines(second, func(str string) error {
		return errors.New("failed to receive the provided string")
	}); err == nil {
		t.Errorf("Failed to receive the callback routine error message")
	}
}

func TestStringsToQtypes(t *testing.T) {
	cases := []struct {
		label    string
		qtypes   []string
		expected []uint16
	}{
		{
			label:    "Empty input",
			qtypes:   []string{},
			expected: []uint16{},
		}, {
			label:    "Valid input",
			qtypes:   []string{"CNAME", "A", "AAAA"},
			expected: []uint16{dns.TypeCNAME, dns.TypeA, dns.TypeAAAA},
		}, {
			label:    "Invalid input",
			qtypes:   []string{"WRONG", "A", "INVALID", "PTR"},
			expected: []uint16{dns.TypeA, dns.TypePTR},
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			for i, got := range StringsToQtypes(c.qtypes) {
				if got != c.expected[i] {
					t.Errorf("Got: %d; Expected: %d", got, c.expected[i])
				}
			}
		}
		t.Run(c.label, f)
	}
}

func TestStringToQtype(t *testing.T) {
	input := []string{"A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "NSEC"}
	expected := []uint16{dns.TypeA, dns.TypeNS, dns.TypeCNAME, dns.TypeSOA, dns.TypePTR, dns.TypeMX, dns.TypeTXT, dns.TypeAAAA, dns.TypeNone}

	for i, str := range input {
		if got := StringToQtype(str); got != expected[i] {
			t.Errorf("Got: %d; Expected: %d", got, expected[i])
		}
	}
}
