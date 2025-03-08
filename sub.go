// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

// FirstProperSubdomain returns the first subdomain name using the provided name and
// Resolver that responds successfully to a DNS query for the NS record type.
func FirstProperSubdomain(ctx context.Context, r *Resolvers, name string) string {
	var domain string
	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")
loop:
	for i := 0; i < len(labels)-1; i++ {
		sub := strings.Join(labels[i:], ".")

		for i := 0; i < maxQueryAttempts; i++ {
			resp, err := r.QueryBlocking(ctx, QueryMsg(sub, dns.TypeNS))
			if err != nil || resp.Rcode == dns.RcodeNameError {
				continue loop
			}
			if resp.Rcode == dns.RcodeSuccess {
				if len(resp.Answer) == 0 {
					continue loop
				}
				if d := AnswersByType(resp, dns.TypeNS); len(d) > 0 {
					domain = sub
					break loop
				}
			}
		}
	}
	return domain
}
