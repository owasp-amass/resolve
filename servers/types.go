// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"net"
	"sync"
	"time"

	"github.com/owasp-amass/resolve/types"
	"golang.org/x/time/rate"
)

type nameserver struct {
	addr  *net.UDPAddr
	xchgs *xchgMgr
	rate  *rateTrack
}

type rrLimiter struct {
	limiter *rate.Limiter
	limit   time.Duration
	ecount  int
	tcount  int
	scount  int
}

type rateTrack struct {
	sync.Mutex
	rrLimiters   map[uint16]*rrLimiter
	lastResponse time.Time
}

// The xchgMgr handles DNS message IDs and identifying messages that have timed out.
type xchgMgr struct {
	sync.Mutex
	xchgs map[string]types.Request
}
