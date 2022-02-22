// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"github.com/miekg/dns"
)

// ResolverErrRcode is our made up rcode to indicate an interface error.
const ResolverErrRcode = 100

// TimeoutRcode is our made up rcode to indicate that a query timed out.
const TimeoutRcode = 101

// The priority levels for Resolver DNS queries.
const (
	AttemptsPriorityLow      int = 5
	AttemptsPriorityNormal   int = 10
	AttemptsPriorityHigh     int = 25
	AttemptsPriorityCritical int = 50
)

// Retry is the definition for the callbacks used in the Resolver interface.
type Retry func(times int, priority int, msg *dns.Msg) bool

// RetryCodes are the rcodes that cause the resolver to suggest trying again.
var RetryCodes = []int{
	TimeoutRcode,
	ResolverErrRcode,
}

// PoolRetryCodes are the rcodes that cause the pool to suggest trying again.
var PoolRetryCodes = []int{
	TimeoutRcode,
	ResolverErrRcode,
	dns.RcodeFormatError,
	dns.RcodeRefused,
	dns.RcodeServerFailure,
	dns.RcodeNotImplemented,
}

// RetryPolicy is the default policy used to determine if a DNS query should be performed again.
func RetryPolicy(times, priority int, msg *dns.Msg) bool {
	return checkPolicy(times, priority, msg, RetryCodes)
}

// PoolRetryPolicy is the default policy used by the resolver pool
// to determine if a DNS query should be performed again.
func PoolRetryPolicy(times, priority int, msg *dns.Msg) bool {
	return checkPolicy(times, priority, msg, PoolRetryCodes)
}

func checkPolicy(times, priority int, msg *dns.Msg, codes []int) bool {
	if attemptsExceeded(times, priority) {
		return false
	}

	if msg == nil {
		return false
	}

	for _, code := range codes {
		if msg.Rcode == code {
			return true
		}
	}
	return false
}

func attemptsExceeded(times, priority int) bool {
	var attempts int

	switch priority {
	case PriorityCritical:
		attempts = AttemptsPriorityCritical
	case PriorityHigh:
		attempts = AttemptsPriorityHigh
	case PriorityNormal:
		attempts = AttemptsPriorityNormal
	case PriorityLow:
		attempts = AttemptsPriorityLow
	}

	return times > attempts
}
