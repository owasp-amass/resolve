// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSendResponseDelivers(t *testing.T) {
	ch := make(chan *dns.Msg, 1)
	r := NewRequest(new(dns.Msg), ch)

	resp := new(dns.Msg)
	r.SendResponse(resp)

	select {
	case got := <-ch:
		if got != resp {
			t.Fatal("SendResponse delivered the wrong message")
		}
	default:
		t.Fatal("SendResponse did not deliver the response")
	}
}

// TestSendResponseClosedChannel is the regression test for the send-on-closed
// channel panic: a response that arrives after the caller has stopped
// listening and closed the channel must be dropped, not crash the process.
func TestSendResponseClosedChannel(t *testing.T) {
	ch := make(chan *dns.Msg, 1)
	close(ch)
	r := NewRequest(new(dns.Msg), ch)

	// Neither of these may panic.
	r.SendResponse(new(dns.Msg))
	r.NoResponse()
}

// TestSendResponseFullBuffer verifies a duplicate response for a request whose
// buffer is already full is dropped rather than blocking the resolver
// goroutine forever.
func TestSendResponseFullBuffer(t *testing.T) {
	ch := make(chan *dns.Msg, 1)
	r := NewRequest(new(dns.Msg), ch)

	r.SendResponse(new(dns.Msg)) // fills the buffer

	done := make(chan struct{})
	go func() {
		r.SendResponse(new(dns.Msg)) // must not block
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SendResponse blocked on a full buffer")
	}
}
