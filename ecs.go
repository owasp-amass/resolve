// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ClientSubnetCheck ensures that the provided resolver does not send the EDNS client subnet information.
// The function returns the DNS reply size limit in number of bytes.
func ClientSubnetCheck(resolver string) error {
	client := dns.Client{
		Net:     "udp",
		UDPSize: dns.DefaultMsgSize,
		Timeout: 2 * time.Second,
	}

	msg := QueryMsg("o-o.myaddr.l.google.com", dns.TypeTXT)
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil || (!resp.Authoritative && !resp.RecursionAvailable) {
		return fmt.Errorf("ClientSubnetCheck: Failed to query 'o-o.myaddr.l.google.com' using the resolver at %s: %v", resolver, err)
	}

	err = fmt.Errorf("ClientSubnetCheck: No answers returned from 'o-o.myaddr.l.google.com' using the resolver at %s", resolver)
	if ans := ExtractAnswers(resp); len(ans) > 0 {
		if records := AnswersByType(ans, dns.TypeTXT); len(records) > 0 {
			err = nil
			for _, rr := range records {
				if strings.HasPrefix(rr.Data, "edns0-client-subnet") {
					return fmt.Errorf("ClientSubnetCheck: The EDNS client subnet data was sent through using resolver %s", resolver)
				}
			}
		}
	}
	return err
}
