// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func NsecTraversal(ctx context.Context, r *Resolvers, domain string) ([]*dns.NSEC, bool, error) {
	select {
	case <-r.done:
		return nil, true, errors.New("resolver: The resolver has been stopped")
	default:
	}

	found := true
	domain = domain + "."
	var results []*dns.NSEC
	names := make(map[string]struct{})
	for next := domain; found; {
		found = false

		if nsec, err := searchGap(ctx, r, next, domain); err == nil {
			if _, yes := names[nsec.NextDomain]; yes {
				break
			}
			names[nsec.NextDomain] = struct{}{}

			found = true
			next = nsec.NextDomain
			results = append(results, nsec)
		}

		if next == domain {
			break
		}
	}
	return results, false, nil
}

func searchGap(ctx context.Context, r *Resolvers, name, domain string) (*dns.NSEC, error) {
	msg, err := r.QueryBlocking(ctx, WalkMsg(name, dns.TypeNSEC))
	if err != nil || len(msg.Answer) == 0 {
		return nil, fmt.Errorf("NsecTraversal: Query for %s NSEC record failed: %v", name, err)
	}

	for _, rr := range append(msg.Answer, msg.Ns...) {
		if nsec, ok := rr.(*dns.NSEC); ok {
			return nsec, nil
		}
	}

	return nil, fmt.Errorf("NsecTraversal: NSEC record not found")
}
