// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"strings"

	"github.com/miekg/dns"
)

// ClientSubnetCheck ensures that all the resolvers in the pool respond to the query
// and do not send the EDNS client subnet information.
func (r *Resolvers) ClientSubnetCheck() {
	all := r.pool.AllResolvers()
	alen := len(all)
	ch := make(chan *dns.Msg, alen)
	msgsToRes := make(map[string]*resolver)

	for _, res := range all {
		msg := QueryMsg("o-o.myaddr.l.google.com", dns.TypeTXT)
		msgsToRes[xchgKey(msg.Id, msg.Question[0].Name)] = res
		r.writeMsg(&request{
			Res:    res,
			Msg:    msg,
			Result: ch,
		})
	}

	retries := make(map[string]struct{})
	for i := 0; i < alen; i++ {
		resp := <-ch
		var failed bool
		// pull the resolver associated with this message
		key := xchgKey(resp.Id, resp.Question[0].Name)
		res, found := msgsToRes[key]
		if !found {
			continue
		}
		delete(msgsToRes, key)
		// give resolvers one additional chance to respond
		if _, already := retries[res.address.IP.String()]; !already && resp.Rcode == RcodeNoResponse {
			i--
			retries[res.address.IP.String()] = struct{}{}
			msg := QueryMsg("o-o.myaddr.l.google.com", dns.TypeTXT)
			msgsToRes[xchgKey(msg.Id, msg.Question[0].Name)] = res
			r.writeMsg(&request{
				Res:    res,
				Msg:    msg,
				Result: ch,
			})
			continue
		}
		// check if the resolver responded, but did not return a successful response
		if resp.Rcode != dns.RcodeSuccess || (!resp.Authoritative && !resp.RecursionAvailable) {
			failed = true
		}
		// check if the response included the expected record
		if ans := ExtractAnswers(resp); !failed && len(ans) > 0 {
			if records := AnswersByType(ans, dns.TypeTXT); !failed && len(records) > 0 {
				for _, rr := range records {
					if strings.HasPrefix(rr.Data, "edns0-client-subnet") {
						failed = true
					}
				}
			} else {
				failed = true
			}
		} else {
			failed = true
		}
		// discontinue usage of the resolver when the check fails
		if res != nil && failed {
			res.stop()
		}
	}
}
