// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func (ns *nameserver) NsecTraversal(domain string, conns types.Conn) ([]*dns.NSEC, error) {
	domain = domain + "." // Ensure the domain name has a period at the end

	var results []*dns.NSEC
	names := make(map[string]struct{})
	for next := domain; true; {
		select {
		case <-ns.done:
			return nil, errors.New("the resolver pool has been stopped")
		default:
		}

		nsec, err := ns.searchGap(next, conns)
		if err != nil {
			return results, err
		}

		if _, yes := names[nsec.NextDomain]; yes {
			break
		}
		names[nsec.NextDomain] = struct{}{}

		next = nsec.NextDomain
		results = append(results, nsec)
		if next == domain {
			break
		}
	}

	return results, nil
}

func (ns *nameserver) searchGap(name string, conns types.Conn) (*dns.NSEC, error) {
	for i := 0; i < 10; i++ {
		ch := make(chan *dns.Msg, 1)
		defer close(ch)

		req := RequestPool.Get().(*request)
		req.result = ch
		req.serv = ns
		req.msg = utils.WalkMsg(name, dns.TypeNSEC)

		ns.SendRequest(req, conns)
		resp := <-ch

		if resp.Rcode == dns.RcodeNameError {
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
