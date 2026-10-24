// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
)

func TCPExchange(req types.Request, timeout time.Duration) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}

	msg := req.Message().Copy()
	// A response carrying no question cannot be matched to its request, and
	// callers index resp.Question[0]. The UDP path already drops these in
	// conn.readMessages; do the same for the TCP retry.
	if resp, _, err := client.Exchange(msg, req.Server().Address().String()); err == nil && resp != nil && len(resp.Question) > 0 {
		go func() {
			req.SendResponse(resp)
			req.Release()
		}()
		return
	}

	go func() {
		req.NoResponse()
		req.Release()
	}()
}
