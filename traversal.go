// Copyright © by Jeff Foley 2022-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"strings"
)

// FQDNToRegistered executes the provided callback routine for domain names, starting
// with the FQDN to the registered domain name, removing one label with each execution.
// The process stops if the callback routine returns true, indicating completion.
func FQDNToRegistered(fqdn, registered string, callback func(domain string) bool) {
	base := len(strings.Split(registered, "."))
	labels := strings.Split(fqdn, ".")

	max := len(labels) - base
	for i := 0; i <= max; i++ {
		if callback(strings.Join(labels[i:], ".")) {
			break
		}
	}
}

// RegisteredToFQDN executes the provided callback routine for domain names, starting
// with the registered domain name to the FQDN, adding one label with each execution.
// The process stops if the callback routine returns true, indicating completion.
func RegisteredToFQDN(registered, fqdn string, callback func(domain string) bool) {
	base := len(strings.Split(registered, "."))
	labels := strings.Split(fqdn, ".")

	for i := len(labels) - base; i >= 0; i-- {
		if callback(strings.Join(labels[i:], ".")) {
			break
		}
	}
}
