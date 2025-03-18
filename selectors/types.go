// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"sync"
	"time"

	"github.com/owasp-amass/resolve"
)

type Selector interface {
	// Get returns a nameserverr managed by the selector.
	Get(fqdn string) *resolve.Nameserver

	// Lookup returns the nameserver with the matching address.
	Lookup(addr string) *resolve.Nameserver

	// Add adds a nameserver to the selector pool.
	Add(ns *resolve.Nameserver)

	// Remove removes a nameserver from the selector pool.
	Remove(ns *resolve.Nameserver)

	// All returns all the nameservers currently managed by the selector.
	All() []*resolve.Nameserver

	// Close releases all resources allocated by the selector.
	Close()
}

type Random struct {
	sync.Mutex
	list   []*resolve.Nameserver
	lookup map[string]*resolve.Nameserver
}

type Authoritative struct {
	sync.Mutex
	timeout       time.Duration
	list          []*resolve.Nameserver
	lookup        map[string]*resolve.Nameserver
	roots         []*resolve.Nameserver
	fqdnToServers map[string][]string
	fqdnToNSs     map[string][]*resolve.Nameserver
	serverToNSs   map[string]*resolve.Nameserver
}
