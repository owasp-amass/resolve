// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

type Nameserver interface {
	Address() *net.UDPAddr
	XchgManager() XchgManager
	RateMonitor() RateTrack
	SendRequest(req Request, conns Conn) error
	RequestResponse(resp *dns.Msg, at time.Time)
	NsecTraversal(domain string, conns Conn) ([]*dns.NSEC, error)
	Close()
}

type RateTrack interface {
	Take()
	ReportRTT(rtt time.Duration)
}

// XchgManager handles DNS message IDs and identifying messages that have timed out.
type XchgManager interface {
	Add(req Request) error
	Remove(id uint16, name string) (Request, bool)
	RemoveExpired(timeout time.Duration) []Request
	RemoveAll() []Request
	Delete(keys []string) []Request
}
