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
	minInterval         = 500 * time.Millisecond
	numIntervalSeconds  = 5
	rateUpdateInterval  = numIntervalSeconds * time.Second
	minUpdateSampleSize = 10
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
	r.Lock()
	l := r.limiter
	r.Unlock()

	_ = l.Wait(context.TODO())
}

// ReportResponseTime provides the response time for a request for the domain name provided in the sub parameter.
func (r *rateTrack) ReportResponseTime(sub string, delta time.Duration) {
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

	if r.first {
		defer r.update()
	}
	r.Unlock()
}

func (rt *rateTrack) update() {
	rt.Lock()
	defer rt.Unlock()

	if rt.first {
		rt.first = false
	} else if rt.count < minUpdateSampleSize {
		return
	}

	limit := rate.Every(rt.avg)
	// update the QPS rate limiter and reset counters
	rt.limiter = rate.NewLimiter(limit, 1)
	rt.avg = 0
	rt.count = 0
}
