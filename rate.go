// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	numIntervalSeconds  = 5
	minUpdateSampleSize = 10
	minInterval         = 500 * time.Millisecond
	rateUpdateInterval  = numIntervalSeconds * time.Second
)

type rateTrack struct {
	sync.Mutex
	limiter    *rate.Limiter
	avg        time.Duration
	count      int
	first      bool
	updateTime time.Time
}

func newRateTrack() *rateTrack {
	limit := rate.Every(100 * time.Millisecond)

	return &rateTrack{
		limiter: rate.NewLimiter(limit, 1),
		first:   true,
	}
}

// Take blocks as required by the implemented rate limiter.
func (r *rateTrack) Take() {
	_ = r.limiter.Wait(context.TODO())
}

// ReportResponseTime provides the response time for a request.
func (r *rateTrack) ReportRTT(rtt time.Duration) {
	r.Lock()
	defer r.Unlock()

	if rtt > minInterval {
		rtt = minInterval
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
		r.updateTime = time.Now()
	} else if r.count >= minUpdateSampleSize && time.Since(r.updateTime) >= rateUpdateInterval {
		r.update()
		r.updateTime = time.Now()
	}
}

// update the QPS rate limiter and reset counters
func (r *rateTrack) update() {
	r.limiter.SetLimit(rate.Every(r.avg))
	r.avg = 0
	r.count = 0
}
