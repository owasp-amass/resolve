// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUpdateRateLimiters(t *testing.T) {
	rt := newRateTrack()
	_ = rt.Wait(context.Background(), 1)

	rt.Lock()
	start := rt.rrLimiters[1].limiter.Limit()
	rt.Unlock()

	rt.ReportResponse(1, dns.RcodeRefused, time.Duration(0))

	rt.Lock()
	first := rt.rrLimiters[1].limiter.Limit()
	rt.Unlock()
	// the QPS should now be lower
	if first >= start {
		t.Errorf("Unexpected QPS, expected QPS lower than %f, got %f", start, first)
	}

	_ = rt.Wait(context.Background(), 1)
	rt.ReportResponse(1, dns.RcodeSuccess, 10*time.Millisecond)

	rt.Lock()
	second := rt.rrLimiters[1].limiter.Limit()
	rt.Unlock()

	// the QPS should now be higher
	if second <= first || second != 100 {
		t.Errorf("Unexpected QPS, expected QPS of %d, got %f", 100, second)
	}
}
