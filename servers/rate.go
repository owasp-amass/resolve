// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	startingLimit     = 50 * time.Millisecond
	minimumLimit      = 10 * time.Millisecond
	maximumLimit      = 200 * time.Millisecond
	errorDelay        = 2 * time.Millisecond
	timeoutDelay      = 500 * time.Microsecond
	errorMaxBackoff   = 20 * time.Millisecond
	timeoutMaxBackoff = 5 * time.Millisecond
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
	if rCode < dns.RcodeSuccess || rCode > dns.RcodeBadCookie {
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

	switch rCode {
	case dns.RcodeRefused:
		fallthrough
	case dns.RcodeServerFailure:
		rl.errors++
		delay := utils.TruncatedExponentialBackoff(rl.errors, errorDelay, errorMaxBackoff)
		r.setLimitLocked(rl, rl.limit+delay)
		return
	case types.RcodeNoResponse:
		rl.timeouts++
		if rl.timeouts > 1 {
			delay := utils.TruncatedExponentialBackoff(
				rl.timeouts-1, timeoutDelay, timeoutMaxBackoff)
			r.setLimitLocked(rl, rl.limit+delay)
		}
		return
	}

	if rtt < rl.limit {
		r.setLimitLocked(rl, (rl.limit+rtt)/2)
	}
	rl.errors = 0
	rl.timeouts = 0
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
