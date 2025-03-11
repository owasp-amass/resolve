// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	rt.ReportResponseTime(domain, 500*time.Millisecond)

	tracker.Lock()
	limit := tracker.rate.Limit()
	tracker.Unlock()
	// the QPS should now be lower
	if limit > 3 {
		t.Errorf("Unexpected QPS, expected QPS lower than %d, got %f", 3, limit)
	}

	tracker.Lock()
	tracker.avg = 50 * time.Millisecond
	tracker.count = minUpdateSampleSize
	tracker.Unlock()
	tracker.update()

	tracker.Lock()
	limit = tracker.rate.Limit()
	tracker.Unlock()
	// the QPS should now be higher
	if limit < 20 || limit > 21 {
		t.Errorf("Unexpected QPS, expected QPS of %d, got %f", 20, limit)
	}
}
