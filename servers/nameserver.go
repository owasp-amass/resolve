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
		go func(req types.Request) {
			req.NoResponse()
			req.Release()
		}(req)
	}
}

func (ns *nameserver) SendRequest(req types.Request, conns types.Conn) error {
	if req.Message() == nil {
		return errors.New("the request message is nil")
	}
	msg := req.Message().Copy()

	req.SetServer(ns)
	if err := ns.xchgs.Add(req); err != nil {
		return err
	}

	ns.rate.Take()
	if err := conns.WriteMsg(msg, ns); err != nil {
		msg := req.Message()

		if _, found := ns.xchgs.Remove(msg.Id, msg.Question[0].Name); found {
			return err
		}
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

	req.SendResponse(resp)
	req.Release()
}
