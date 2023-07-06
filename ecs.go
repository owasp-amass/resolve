// Copyright © by Jeff Foley 2021-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"github.com/miekg/dns"
)

// ClientSubnetCheck ensures that all the resolvers in the pool respond to the query
// and do not send the EDNS client subnet information.
func (r *Resolvers) ClientSubnetCheck() {
	all := r.pool.AllResolvers()
	alen := len(all)
	ch := make(chan *dns.Msg, alen)
	msgsToRes := make(map[string]*resolver)

	send := func(res *resolver) {
		msg := QueryMsg("o-o.myaddr.l.google.com", dns.TypeTXT)
		msgsToRes[xchgKey(msg.Id, msg.Question[0].Name)] = res
		r.writeReq(&request{
			Res:    res,
			Msg:    msg,
			Result: ch,
		})
	}

	for _, res := range all {
		send(res)
	}

	retries := make(map[string]struct{})
	for i := 0; i < alen; i++ {
		resp := <-ch

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
			send(res)
			continue
		}
		// check if the resolver responded, but did not return a successful response
		if resp.Rcode != dns.RcodeSuccess || (!resp.Authoritative && !resp.RecursionAvailable) {
			res.stop()
			continue
		}

		failed := true
		// check if the response included the expected record
		if ans := ExtractAnswers(resp); len(ans) > 0 {
			if records := AnswersByType(ans, dns.TypeTXT); len(records) > 0 {
				failed = false
			}
		}
		// discontinue usage of the resolver when the check fails
		if res != nil && failed {
			res.stop()
		}
	}
}
