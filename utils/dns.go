// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	release := true
	if m, _, err := client.Exchange(req.Message(), req.Server().Address().String()); err == nil {
		select {
		case req.ResultChan() <- m:
		default:
			release = false
		}
	} else {
		req.NoResponse()
	}

	if release {
		req.Release()
	}
}
