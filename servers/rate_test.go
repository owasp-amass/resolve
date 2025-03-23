// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"testing"
	"time"
)

func TestUpdateRateLimiters(t *testing.T) {
	rt := newRateTrack()
	rt.Take()

	rt.ReportRTT(500 * time.Millisecond)

	rt.Lock()
	limit := rt.limiter.Limit()
	rt.Unlock()
	// the QPS should now be lower
	if limit > 3 {
		t.Errorf("Unexpected QPS, expected QPS lower than %d, got %f", 3, limit)
	}

	rt.Lock()
	rt.avg = 50 * time.Millisecond
	rt.count = minUpdateSampleSize
	rt.Unlock()
	rt.update()

	rt.Lock()
	limit = rt.limiter.Limit()
	rt.Unlock()
	// the QPS should now be higher
	if limit < maxLimit || limit > maxLimit+1 {
		t.Errorf("Unexpected QPS, expected QPS of %d, got %f", 15, limit)
	}
}
