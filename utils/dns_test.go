// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

// runQuestionlessTCPServer answers every query with QDCOUNT=0, which is what a
// broken or hostile nameserver can do on the TCP retry.
func runQuestionlessTCPServer(t *testing.T) (string, func()) {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("unable to listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question = nil
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{Listener: l, Handler: mux, ReadTimeout: time.Hour, WriteTimeout: time.Hour}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	return l.Addr().String(), func() { _ = srv.Shutdown() }
}

func TestTCPExchangeDropsQuestionlessResponse(t *testing.T) {
	addr, shutdown := runQuestionlessTCPServer(t)
	defer shutdown()

	ch := make(chan *dns.Msg, 1)
	req := types.NewRequest(utils.QueryMsg("example.com", dns.TypeA), ch)
	req.SetServer(servers.NewNameserver(addr))

	utils.TCPExchange(req, 2*time.Second)

	select {
	case resp := <-ch:
		// Callers index resp.Question[0], so a question-less response must come
		// back as no response rather than being handed on.
		if resp.Rcode != types.RcodeNoResponse {
			t.Fatalf("expected RcodeNoResponse, got rcode %d with %d questions", resp.Rcode, len(resp.Question))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a result")
	}
}
