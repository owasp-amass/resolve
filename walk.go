// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
func (r *Resolvers) NsecTraversal(ctx context.Context, domain string) ([]*dns.NSEC, error) {
	select {
	case <-ctx.Done():
		return nil, errors.New("the context has expired")
	case <-r.done:
		return nil, errors.New("the resolver pool has been stopped")
	default:
	}

	found := true
	var err error
	domain = domain + "."
	var results []*dns.NSEC
	names := make(map[string]struct{})
	for next := domain; found; {
		found = false
		var nsec *dns.NSEC

		nsec, err = r.searchGap(ctx, next, domain)
		if err == nil {
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
	return results, err
}

func (r *Resolvers) searchGap(ctx context.Context, name, domain string) (*dns.NSEC, error) {
	for i := 0; i < maxQueryAttempts; i++ {
		resp, err := r.QueryBlocking(ctx, WalkMsg(name, dns.TypeNSEC))
		if err != nil || resp.Rcode == dns.RcodeNameError {
			break
		}
		if resp.Rcode == dns.RcodeSuccess {
			if len(resp.Answer) == 0 {
				break
			}
			for _, rr := range append(resp.Answer, resp.Ns...) {
				if nsec, ok := rr.(*dns.NSEC); ok {
					return nsec, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("NsecTraversal: %s NSEC record not found", name)
}
