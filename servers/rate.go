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
	maxBackoff    = 5 * time.Millisecond
	startingLimit = 20 * time.Millisecond
	minimumLimit  = 10 * time.Millisecond
	maximumLimit  = 100 * time.Millisecond
	delay         = 500 * time.Microsecond
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

	rl, found := r.rrLimiters[rrType]
	if !found {
		rl = newRRLimiter()
		r.rrLimiters[rrType] = rl
	}

	r.lastResponse = time.Now()
	if rCode == dns.RcodeServerFailure || rCode == dns.RcodeRefused {
		rl.errors++
		rl.limit += utils.TruncatedExponentialBackoff(rl.errors, delay, maxBackoff)
		r.setLimitLocked(rrType, rl.limit)
		return
	} else if rCode == types.RcodeNoResponse {
		if rl.errors > 0 {
			rl.limit += utils.TruncatedExponentialBackoff(rl.errors, delay, maxBackoff)
			r.setLimitLocked(rrType, rl.limit)
		}
		rl.errors++
		return
	}

	if rtt < rl.limit {
		rl.limit -= time.Millisecond
		r.setLimitLocked(rrType, rl.limit)
	}
	rl.errors = 0
}

func (r *rateTrack) setLimitLocked(rrType uint16, limit time.Duration) {
	rl := r.rrLimiters[rrType]

	rl.limit = limit
	if rl.limit < minimumLimit {
		rl.limit = minimumLimit
	}
	if rl.limit > maximumLimit {
		rl.limit = maximumLimit
	}

	rl.limiter.SetLimit(rate.Every(rl.limit))
}
