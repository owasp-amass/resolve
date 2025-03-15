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
	limiter *rate.Limiter
	avg     time.Duration
	count   int
	first   bool
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
func (r *rateTrack) ReportResponseTime(delta time.Duration) {
	var average, count float64

	if delta > minInterval {
		delta = minInterval
	}

	r.Lock()
	r.count++
	count = float64(r.count)
	average = float64(r.avg.Milliseconds())
	average = ((average * (count - 1)) + float64(delta.Milliseconds())) / count
	r.avg = time.Duration(math.Round(average)) * time.Millisecond
	first := r.first
	r.Unlock()

	if first {
		r.update()
	}
}

func (rt *rateTrack) update() {
	rt.Lock()
	defer rt.Unlock()

	if rt.first {
		rt.first = false
	} else if rt.count < minUpdateSampleSize {
		return
	}
	// update the QPS rate limiter and reset counters
	rt.limiter.SetLimit(rate.Every(rt.avg))
	rt.avg = 0
	rt.count = 0
}
