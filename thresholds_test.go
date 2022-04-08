// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestThresholdOptions(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers(1000, "8.8.8.8")
	defer r.Stop()

	var threshold uint64 = 500
	r.SetThresholdOptions(&ThresholdOptions{
		ThresholdValue: threshold,
		CountTimeouts:  true,
	})

	r.Lock()
	if r.options.ThresholdValue != threshold || r.list[0].stats.CountTimeouts != true {
		t.Errorf("failed to set the new threshold options throughout the resolver pool")
	}
	r.Unlock()
}

func TestThresholdContinuousShutdown(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers(10, "8.8.8.8")
	defer r.Stop()

	r.Lock()
	res := r.list[0]
	r.Unlock()

	time.Sleep(thresholdCheckInterval + time.Second)
	select {
	case <-res.done:
		t.Errorf("resolver was shutdown with no threshold value set")
	default:
	}

	var threshold uint64 = 100
	r.SetThresholdOptions(&ThresholdOptions{ThresholdValue: threshold})

	time.Sleep(thresholdCheckInterval + time.Second)

	select {
	case <-res.done:
		t.Errorf("resolver was shutdown with a threshold value set and no stats")
	default:
	}

	res.stats.Lock()
	res.stats.LastSuccess = threshold
	res.stats.Unlock()

	time.Sleep(thresholdCheckInterval + time.Second)

	select {
	case <-res.done:
	default:
		t.Errorf("resolver was not shutdown when the threshold was met")
	}
}

func TestThresholdCumulativeShutdown(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers(10, "8.8.8.8")
	defer r.Stop()

	r.SetThresholdOptions(&ThresholdOptions{
		ThresholdValue:         100,
		CumulativeAccumulation: true,
		CountTimeouts:          true,
		CountFormatErrors:      true,
		CountServerFailures:    true,
		CountNotImplemented:    true,
		CountQueryRefusals:     true,
	})

	r.Lock()
	res := r.list[0]
	r.Unlock()

	res.stats.Lock()
	res.stats.Timeouts = 20
	res.stats.FormatErrors = 20
	res.stats.ServerFailures = 20
	res.stats.NotImplemented = 20
	res.stats.QueryRefusals = 20
	res.stats.Unlock()

	time.Sleep(thresholdCheckInterval + time.Second)

	select {
	case <-res.done:
	default:
		t.Errorf("resolver was not shutdown when the threshold was met")
	}
}

func TestCollectStats(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, statsHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	r := NewResolvers()
	_ = r.AddResolvers(10, addrstr)
	defer r.Stop()

	r.SetThresholdOptions(&ThresholdOptions{
		ThresholdValue:         100,
		CumulativeAccumulation: true,
		CountTimeouts:          true,
		CountFormatErrors:      true,
		CountServerFailures:    true,
		CountNotImplemented:    true,
		CountQueryRefusals:     true,
	})

	r.Lock()
	res := r.list[0]
	r.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("timeout.caffix.net", 1))
	res.stats.Lock()
	if res.stats.Timeouts != 1 || res.stats.LastSuccess != 1 {
		t.Errorf("failed to collect the stat for the request timeout")
	}
	res.stats.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("format.caffix.net", 1))
	res.stats.Lock()
	if res.stats.Timeouts != 1 || res.stats.LastSuccess != 2 {
		t.Errorf("failed to collect the stat for the format error")
	}
	res.stats.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("server.caffix.net", 1))
	res.stats.Lock()
	if res.stats.Timeouts != 1 || res.stats.LastSuccess != 3 {
		t.Errorf("failed to collect the stat for the server failure")
	}
	res.stats.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("notimp.caffix.net", 1))
	res.stats.Lock()
	if res.stats.Timeouts != 1 || res.stats.LastSuccess != 4 {
		t.Errorf("failed to collect the stat for the not implemented error")
	}
	res.stats.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("refused.caffix.net", 1))
	res.stats.Lock()
	if res.stats.Timeouts != 1 || res.stats.LastSuccess != 5 {
		t.Errorf("failed to collect the stat for the query refused error")
	}
	res.stats.Unlock()

	_, _ = r.QueryBlocking(context.Background(), QueryMsg("legit.caffix.net", 1))
	res.stats.Lock()
	if res.stats.LastSuccess != 0 {
		t.Errorf("failed to reset the stat for the last successful request")
	}
	res.stats.Unlock()
}

func statsHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	switch req.Question[0].Name {
	case "timeout.caffix.net.":
		return
	case "format.caffix.net.":
		m.Rcode = dns.RcodeFormatError
	case "server.caffix.net.":
		m.Rcode = dns.RcodeServerFailure
	case "notimp.caffix.net.":
		m.Rcode = dns.RcodeNotImplemented
	case "refused.caffix.net.":
		m.Rcode = dns.RcodeRefused
	case "legit.caffix.net.":
		m.Answer = make([]dns.RR, 1)
		m.Answer[0] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP("192.168.1.1"),
		}
	}
	_ = w.WriteMsg(m)
}
