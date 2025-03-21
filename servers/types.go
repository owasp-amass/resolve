// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

type rateTrack struct {
	sync.Mutex
	limiter *rate.Limiter
	avg     time.Duration
	count   int
	first   bool
}

// The xchgMgr handles DNS message IDs and identifying messages that have timed out.
type xchgMgr struct {
	sync.Mutex
	xchgs map[string]types.Request
}
