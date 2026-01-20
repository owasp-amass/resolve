// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
	"golang.org/x/time/rate"
)

const (
	startingLimit     = 200 * time.Millisecond
	minimumLimit      = 100 * time.Millisecond
	maximumLimit      = 500 * time.Millisecond
	errorDelay        = 200 * time.Millisecond
	timeoutDelay      = 100 * time.Millisecond
	errorMaxBackoff   = 5 * time.Second
	timeoutMaxBackoff = 1 * time.Second
)

func newRateTrack() *rateTrack {
	return &rateTrack{
		rrLimiters: make(map[uint16]*rrLimiter),
	}
}

func newRRLimiter() *rrLimiter {
	return &rrLimiter{
		limit:   startingLimit,
		limiter: rate.NewLimiter(rate.Every(startingLimit), 1),
	}
}

// Wait blocks as long as required by the rate limiter.
func (r *rateTrack) Wait(ctx context.Context, rrType uint16) error {
	if rrType <= dns.TypeNone || rrType > dns.TypeANY {
		return errors.New("invalid RR type for rate limiting")
	}

	r.Lock()
	rl, found := r.rrLimiters[rrType]
	if !found {
		rl = newRRLimiter()
		r.rrLimiters[rrType] = rl
	}
	r.Unlock()

	return rl.limiter.Wait(ctx)
}

// ReportResponse accepts response information for a DNS query request.
func (r *rateTrack) ReportResponse(rrType uint16, rCode int, rtt time.Duration) {
	if rrType <= dns.TypeNone || rrType > dns.TypeANY {
		return
	}
	if rCode < dns.RcodeSuccess || rCode > types.RcodeNoResponse {
		return
	}

	r.Lock()
	defer r.Unlock()
	r.lastResponse = time.Now()

	rl, found := r.rrLimiters[rrType]
	if !found {
		rl = newRRLimiter()
		r.rrLimiters[rrType] = rl
	}

	// check for errors and timeouts to adjust the rate limit accordingly
	switch rCode {
	case dns.RcodeRefused:
		fallthrough
	case dns.RcodeServerFailure:
		rl.ecount++
		delay := utils.TruncatedExponentialBackoff(rl.ecount, errorDelay, errorMaxBackoff)
		r.setLimitLocked(rl, rl.limit+delay)
		rl.scount = 0
		return
	case types.RcodeNoResponse:
		rl.tcount++
		if rl.tcount > 1 { // ignore first timeout
			delay := utils.TruncatedExponentialBackoff(rl.tcount-1, timeoutDelay, timeoutMaxBackoff)
			r.setLimitLocked(rl, rl.limit+delay)
		}
		rl.scount = 0
		return
	}

	// successful response
	rl.ecount = 0
	rl.tcount = 0
	rl.scount++

	if rl.scount >= 3 && rtt < rl.limit {
		// decrease the limit after 3 consecutive successful responses below the current limit
		r.setLimitLocked(rl, (rl.limit+rtt)/2)
	} else if rtt > rl.limit {
		// increase the limit if the response time is above the current limit
		r.setLimitLocked(rl, (rl.limit+rtt)/2)
	}
}

func (r *rateTrack) setLimitLocked(rl *rrLimiter, limit time.Duration) {
	rl.limit = limit

	if rl.limit < minimumLimit {
		rl.limit = minimumLimit
	}
	if rl.limit > maximumLimit {
		rl.limit = maximumLimit
	}

	rl.limiter.SetLimit(rate.Every(rl.limit))
}
