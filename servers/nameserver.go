// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

func NewNameserver(addr string) types.Nameserver {
	return newNameserver(addr)
}

func newNameserver(addr string) *nameserver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	var ns *nameserver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		ns = &nameserver{
			addr:  uaddr,
			xchgs: NewXchgMgr(),
			rate:  newRateTrack(),
		}
	}
	return ns
}

func (ns *nameserver) Address() *net.UDPAddr {
	return ns.addr
}

func (ns *nameserver) XchgManager() types.XchgManager {
	return ns.xchgs
}

func (ns *nameserver) RateMonitor() types.RateTrack {
	return ns.rate
}

func (ns *nameserver) Close() {
	// Drain the xchgs of all messages and allow callers to return
	for _, req := range ns.xchgs.RemoveAll() {
		req.NoResponse()
		req.Release()
	}
}

func (ns *nameserver) SendRequest(req types.Request, conns types.Conn) error {
	if req == nil {
		return errors.New("the request is nil")
	}
	if conns == nil {
		return errors.New("the connection is nil")
	}

	ns.rate.Take()
	req.SetSentAt(time.Now())
	msg := req.Message().Copy()

	if err := ns.xchgs.Add(req); err != nil {
		return err
	}

	if err := conns.WriteMsg(msg, ns.addr); err != nil {
		_, _ = ns.xchgs.Remove(msg.Id, msg.Question[0].Name)
		return err
	}
	return nil
}

func (ns *nameserver) RequestResponse(resp *dns.Msg, at time.Time) {
	name := resp.Question[0].Name

	req, found := ns.xchgs.Remove(resp.Id, name)
	if !found {
		return
	}

	rtt := at.Sub(req.SentAt())
	ns.rate.ReportRTT(rtt)

	if resp.Truncated {
		utils.TCPExchange(req, 3*time.Second)
		return
	}

	select {
	case req.RespChan() <- resp:
		req.Release()
	default:
	}
}
