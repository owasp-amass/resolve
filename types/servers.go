// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

type Request interface {
	Server() Nameserver
	SetServer(s Nameserver)
	SentAt() time.Time
	SetSentAt(t time.Time)
	RecvAt() time.Time
	SetRecvAt(t time.Time)
	Message() *dns.Msg
	SetMessage(m *dns.Msg)
	Response() *dns.Msg
	SetResponse(m *dns.Msg)
	ResultChan() chan *dns.Msg
	SetResultChan(c chan *dns.Msg)
	NoResponse()
	Release()
}

type Nameserver interface {
	Address() *net.UDPAddr
	XchgManager() XchgManager
	RateMonitor() RateTrack
	SendRequest(req Request, conns Conn) error
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
	Remove(id uint16, name string) Request
	RemoveExpired() []Request
	RemoveAll() []Request
	Delete(keys []string) []Request
}
