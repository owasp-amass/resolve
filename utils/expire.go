// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	"github.com/owasp-amass/resolve/types"
)

// ExpireRequests ends each of the nameserver's queries that has waited longer
// than timeout for a response, so its sender stops waiting.
func ExpireRequests(ns types.Nameserver, timeout time.Duration) {
	for _, req := range ns.XchgManager().RemoveExpired(timeout) {
		go func(req types.Request) {
			req.NoResponse()
			req.Release()
		}(req)
	}
}
