// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"math/rand"
	"time"
)

func ExponentialBackoff(events int, delay time.Duration) time.Duration {
	return (time.Duration(2^events) * delay) + BackoffJitter(0, delay)
}

func TruncatedExponentialBackoff(events int, delay, max time.Duration) time.Duration {
	backoff := ExponentialBackoff(events, delay)

	if backoff > max {
		backoff = max
	}
	return backoff
}

// BackoffJitter returns a random Duration between the provided min and max parameters.
func BackoffJitter(min, max time.Duration) time.Duration {
	delta := max - min
	if delta <= 0 {
		return time.Duration(0)
	}

	one := delta / 1000
	return min + (time.Duration(rand.Intn(1000)) * one)
}