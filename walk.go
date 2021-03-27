// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func NsecTraversal(ctx context.Context, r Resolver, domain string, priority int) ([]*dns.NSEC, bool, error) {
	if priority != PriorityCritical && priority != PriorityHigh && priority != PriorityLow {
		return nil, false, &ResolveError{
			Err:   fmt.Sprintf("Resolver: Invalid priority parameter: %d", priority),
			Rcode: ResolverErrRcode,
		}
	}

	if r.Stopped() {
		return nil, true, errors.New("Resolver: The resolver has been stopped")
	}

	found := true
	domain = domain + "."
	var results []*dns.NSEC
	names := make(map[string]struct{})
	for next := domain; found; {
		found = false

		if nsec, err := searchGap(ctx, r, next, domain, priority); err == nil {
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

func searchGap(ctx context.Context, r Resolver, name, domain string, priority int) (*dns.NSEC, error) {
	msg, err := r.Query(ctx, WalkMsg(name, dns.TypeNSEC), priority, RetryPolicy)
	if err != nil || msg == nil {
		return nil, fmt.Errorf("NsecTraversal: Query for %s NSEC record failed: %v", name, err)
	}

	for _, rr := range append(msg.Answer, msg.Ns...) {
		if nsec, ok := rr.(*dns.NSEC); ok {
			return nsec, nil
		}
	}

	return nil, fmt.Errorf("NsecTraversal: Resolver %s: NSEC record not found", r.String())
}
