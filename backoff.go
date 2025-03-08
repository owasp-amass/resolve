// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math"
	"math/rand"
	"time"
)

const numOfUnits int = 100

// ExponentialBackoff returns a Duration equal to 2^events multiplied by the provided delay
// and jitter added equal to [0,delay).
func ExponentialBackoff(events int, delay time.Duration) time.Duration {
	return (time.Duration(math.Pow(2, float64(events))) * delay) + BackoffJitter(0, delay)
}

// TruncatedExponentialBackoff returns a Duration equal to ExponentialBackoff with a provided
// maximum Duration used to truncate the result.
func TruncatedExponentialBackoff(events int, delay, max time.Duration) time.Duration {
	if backoff := ExponentialBackoff(events, delay); backoff < max {
		return backoff
	}
	return max
}

// BackoffJitter returns a random Duration between the provided min and max parameters.
func BackoffJitter(min, max time.Duration) time.Duration {
	if max < min {
		return time.Duration(0)
	}
	if period := max - min; period > time.Duration(numOfUnits) {
		return min + (time.Duration(rand.Intn(numOfUnits)) * (period / time.Duration(numOfUnits)))
	}
	return min
}
