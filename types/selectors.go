// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

type Selector interface {
	// Get returns a nameserverr managed by the selector.
	Get(fqdn string) Nameserver

	// Lookup returns the nameserver with the matching address.
	Lookup(addr string) Nameserver

	// Add adds a nameserver to the selector pool.
	Add(ns Nameserver)

	// Remove removes a nameserver from the selector pool.
	Remove(ns Nameserver)

	// All returns all the nameservers currently managed by the selector.
	All() []Nameserver

	// Close releases all resources allocated by the selector.
	Close()
}
