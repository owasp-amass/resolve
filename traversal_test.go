// Copyright © by Jeff Foley 2022-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"reflect"
	"testing"
)

func TestFQDNToRegistered(t *testing.T) {
	var got []string
	tests := []struct {
		name       string
		fqdn       string
		registered string
		expected   []string
		callback   func(domain string) bool
	}{
		{
			name:       "Full traversal",
			fqdn:       "www.accessphysiotherapy.com.ezproxy.utica.edu",
			registered: "utica.edu",
			expected: []string{
				"www.accessphysiotherapy.com.ezproxy.utica.edu",
				"accessphysiotherapy.com.ezproxy.utica.edu",
				"com.ezproxy.utica.edu",
				"ezproxy.utica.edu",
				"utica.edu",
			},
			callback: func(domain string) bool {
				got = append(got, domain)
				return false
			},
		},
		{
			name:       "Only one domain name",
			fqdn:       "www.accessphysiotherapy.com.ezproxy.utica.edu",
			registered: "utica.edu",
			expected:   []string{"www.accessphysiotherapy.com.ezproxy.utica.edu"},
			callback: func(domain string) bool {
				got = append(got, domain)
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = []string{}

			FQDNToRegistered(tt.fqdn, tt.registered, tt.callback)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestRegisteredToFQDN(t *testing.T) {
	var got []string
	tests := []struct {
		name       string
		fqdn       string
		registered string
		expected   []string
		callback   func(domain string) bool
	}{
		{
			name:       "Full traversal",
			fqdn:       "www.accessphysiotherapy.com.ezproxy.utica.edu",
			registered: "utica.edu",
			expected: []string{
				"utica.edu",
				"ezproxy.utica.edu",
				"com.ezproxy.utica.edu",
				"accessphysiotherapy.com.ezproxy.utica.edu",
				"www.accessphysiotherapy.com.ezproxy.utica.edu",
			},
			callback: func(domain string) bool {
				got = append(got, domain)
				return false
			},
		},
		{
			name:       "Only one domain name",
			fqdn:       "www.accessphysiotherapy.com.ezproxy.utica.edu",
			registered: "utica.edu",
			expected:   []string{"utica.edu"},
			callback: func(domain string) bool {
				got = append(got, domain)
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = []string{}

			RegisteredToFQDN(tt.registered, tt.fqdn, tt.callback)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, got)
			}
		})
	}
}
