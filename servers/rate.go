// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"context"
	"math"
	"time"

	"golang.org/x/time/rate"
)

const (
	minLimit            = 1
	maxLimit            = 15
	minUpdateSampleSize = 10
	maxInterval         = time.Second
)

func newRateTrack() *rateTrack {
	limit := rate.Every(100 * time.Millisecond)

	return &rateTrack{
		limiter: rate.NewLimiter(limit, 1),
		first:   true,
	}
}

// Take blocks as long as required by the rate limiter.
func (r *rateTrack) Take() {
	_ = r.limiter.Wait(context.TODO())
}

// ReportRTT accepts a round-trip-time for a DNS query request.
func (r *rateTrack) ReportRTT(rtt time.Duration) {
	r.Lock()
	defer r.Unlock()

	if rtt > maxInterval {
		rtt = maxInterval
	}

	r.count++
	count := float64(r.count)
	average := float64(r.avg.Milliseconds())
	average = ((average * (count - 1)) + float64(rtt.Milliseconds())) / count
	r.avg = time.Duration(math.Round(average)) * time.Millisecond
	first := r.first

	if first {
		r.update()
		r.first = false
	} else if r.count >= minUpdateSampleSize {
		r.update()
	}
}

// update the QPS rate limiter and reset counters
func (r *rateTrack) update() {
	limit := rate.Every(r.avg)

	if limit > maxLimit {
		limit = maxLimit
	} else if limit < minLimit {
		limit = minLimit
	}

	r.limiter.SetLimit(limit)
	r.avg = 0
	r.count = 0
}
