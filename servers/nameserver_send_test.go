// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

// failConn is a types.Conn whose writes always fail.
type failConn struct{}

func (failConn) Close()                                    {}
func (failConn) WriteMsg(*dns.Msg, types.Nameserver) error { return errors.New("write failed") }

// TestSendRequestErrorRemovesFromXchgs verifies that when a send fails the
// request is not left registered in the nameserver's exchange manager. A
// leaked request is a correctness hazard: the caller releases it back to the
// sync.Pool, and a later response can then match the recycled request,
// deliver to the wrong channel, and release it a second time.
func TestSendRequestErrorRemovesFromXchgs(t *testing.T) {
	ns := newNameserver("127.0.0.1")
	if ns == nil {
		t.Fatal("failed to create the nameserver")
	}

	msg := utils.QueryMsg("example.com", dns.TypeA)
	req := types.NewRequest(msg, make(chan *dns.Msg, 1))

	if err := ns.SendRequest(context.Background(), req, failConn{}); err == nil {
		t.Fatal("SendRequest did not report the write failure")
	}
	if _, found := ns.XchgManager().Remove(msg.Id, msg.Question[0].Name); found {
		t.Fatal("a failed request was left in the exchange manager")
	}
}

// TestSendRequestNilMessage confirms a nil message is rejected before the
// request is ever registered.
func TestSendRequestNilMessage(t *testing.T) {
	ns := newNameserver("127.0.0.1")
	if ns == nil {
		t.Fatal("failed to create the nameserver")
	}

	req := types.NewRequest(nil, make(chan *dns.Msg, 1))
	if err := ns.SendRequest(context.Background(), req, failConn{}); err == nil {
		t.Fatal("SendRequest accepted a request with a nil message")
	}
}
