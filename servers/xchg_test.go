// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"strings"
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
)

func TestXchgAddRemove(t *testing.T) {
	name := "caffix.net"
	xchg := NewXchgMgr()
	msg := utils.QueryMsg(name, dns.TypeA)

	req := types.RequestPool.Get().(types.Request)
	req.SetMessage(msg)

	if err := xchg.Add(req); err != nil {
		t.Errorf("Failed to add the request")
	}
	if err := xchg.Add(req); err == nil {
		t.Errorf("Failed to detect the same request added twice")
	}

	ret := xchg.Remove(msg.Id, msg.Question[0].Name)
	resp := ret.Message()

	if ret == nil || resp == nil || name != strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name)) {
		t.Errorf("Did not find and remove the message from the data structure")
	}
	ret = xchg.Remove(msg.Id, msg.Question[0].Name)
	if ret != nil {
		t.Errorf("Did not return nil when attempting to remove an element for the second time")
	}
	if err := xchg.Add(req); err != nil {
		t.Errorf("Failed to add the request after being removed")
	}
}

func TestXchgRemoveExpired(t *testing.T) {
	xchg := NewXchgMgr()
	names := []string{"caffix.net", "www.caffix.net", "blog.caffix.net"}

	for _, name := range names {
		msg := utils.QueryMsg(name, dns.TypeA)
		req := types.RequestPool.Get().(types.Request)
		req.SetMessage(msg)
		req.SetSentAt(time.Now())

		if err := xchg.Add(req); err != nil {
			t.Errorf("Failed to add the request")
		}
	}
	// Add one request that should not be removed with the others
	name := "vpn.caffix.net"
	msg := utils.QueryMsg(name, dns.TypeA)
	req := types.RequestPool.Get().(types.Request)
	req.SetMessage(msg)
	req.SetSentAt(time.Now().Add(3 * time.Second))

	if err := xchg.Add(req); err != nil {
		t.Errorf("Failed to add the request")
	}
	if len(xchg.RemoveExpired(time.Second)) > 0 {
		t.Errorf("The removeExpired method returned requests too early")
	}

	time.Sleep(1500 * time.Millisecond)
	set := stringset.New(names...)
	defer set.Close()

	for _, req := range xchg.RemoveExpired(time.Second) {
		name := strings.ToLower(utils.RemoveLastDot(req.Message().Question[0].Name))

		set.Remove(name)
	}
	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeExpired")
	}
}

func TestXchgRemoveAll(t *testing.T) {
	xchg := NewXchgMgr()
	names := []string{"caffix.net", "www.caffix.net", "blog.caffix.net"}

	for _, name := range names {
		msg := utils.QueryMsg(name, dns.TypeA)
		req := types.RequestPool.Get().(types.Request)
		req.SetMessage(msg)

		if err := xchg.Add(req); err != nil {
			t.Errorf("Failed to add the request")
		}
	}

	set := stringset.New(names...)
	defer set.Close()

	for _, req := range xchg.RemoveAll() {
		name := strings.ToLower(utils.RemoveLastDot(req.Message().Question[0].Name))

		set.Remove(name)
	}
	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeAll")
	}
}
