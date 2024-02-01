// Copyright © by Jeff Foley 2022-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"testing"
	"time"
)

func TestUpdateRateLimiters(t *testing.T) {
	rt := NewRateTracker()
	defer rt.Stop()

	domain := "owasp.org"
	// add the name servers to the rate tracker
	rt.Take(domain)
	tracker := rt.getDomainRateTracker(domain)

	tracker.Lock()
	qps := tracker.qps
	tracker.Unlock()
	num := qps / 2
	// set a large number of timeouts
	for i := 0; i < num; i++ {
		rt.Success(domain)
	}
	for i := 0; i < num; i++ {
		rt.Timeout(domain)
	}
	time.Sleep(rateUpdateInterval + (rateUpdateInterval / 2))

	tracker.Lock()
	qps2 := tracker.qps
	tracker.Unlock()
	// the QPS should now be lower
	if qps2 >= qps {
		t.Errorf("Unexpected QPS, expected QPS lower than %d, got %d", qps, qps2)
	}

	tracker.Lock()
	succ := tracker.success
	tout := tracker.timeout
	tracker.Unlock()
	// check that the counters have been cleared
	if succ != 0 || tout != 0 {
		t.Errorf("Unexpected counter values, Success Counter %d, Timeout Counter %d", succ, tout)
	}

	tracker.Lock()
	qps = tracker.qps
	tracker.Unlock()
	// set a large number of successes
	for i := 0; i < qps; i++ {
		rt.Success(domain)
	}
	time.Sleep(rateUpdateInterval + (rateUpdateInterval / 2))

	tracker.Lock()
	qps2 = tracker.qps
	tracker.Unlock()
	// the QPS should now be higher
	if qps2 <= qps {
		t.Errorf("Unexpected QPS, expected QPS higher than %d, got %d", qps, qps2)
	}
}
