// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolve

import (
	"strings"
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

func TestXchgAddRemove(t *testing.T) {
	name := "caffix.net"
	xchg := newXchgManager()
	msg := QueryMsg(name, dns.TypeA)

	if err := xchg.add(&resolveRequest{
		ID:    msg.Id,
		Name:  name,
		Qtype: dns.TypeA,
		Msg:   msg,
	}); err != nil {
		t.Errorf("Failed to add the request")
	}

	req := xchg.remove(msg.Id, msg.Question[0].Name)
	if req == nil || req.Msg == nil || name != strings.ToLower(RemoveLastDot(req.Msg.Question[0].Name)) {
		t.Errorf("Did not find and remove the message from the data structure")
	}
}

func TestXchgUpdateTimestamp(t *testing.T) {
	name := "caffix.net"
	xchg := newXchgManager()
	msg := QueryMsg(name, dns.TypeA)

	req := &resolveRequest{
		ID:    msg.Id,
		Name:  name,
		Qtype: dns.TypeA,
		Msg:   msg,
	}

	if !req.Timestamp.IsZero() {
		t.Errorf("Expected the new request to have a zero value timestamp")
	}

	if err := xchg.add(req); err != nil {
		t.Errorf("Failed to add the request")
	}
	xchg.updateTimestamp(msg.Id, name)

	req = xchg.remove(msg.Id, msg.Question[0].Name)
	if req == nil || req.Timestamp.IsZero() {
		t.Errorf("Expected the updated request to not have a zero value timestamp")
	}
}

func TestXchgRemoveExpired(t *testing.T) {
	xchg := newXchgManager()
	names := []string{"caffix.net", "www.caffix.net", "blog.caffix.net"}

	QueryTimeout = time.Second
	for _, name := range names {
		msg := QueryMsg(name, dns.TypeA)
		if err := xchg.add(&resolveRequest{
			ID:        msg.Id,
			Name:      name,
			Qtype:     dns.TypeA,
			Msg:       msg,
			Timestamp: time.Now(),
		}); err != nil {
			t.Errorf("Failed to add the request")
		}
	}

	// Add one request that should not be removed with the others
	name := "vpn.caffix.net"
	msg := QueryMsg(name, dns.TypeA)
	if err := xchg.add(&resolveRequest{
		ID:        msg.Id,
		Name:      name,
		Qtype:     dns.TypeA,
		Msg:       msg,
		Timestamp: time.Now().Add(3 * time.Second),
	}); err != nil {
		t.Errorf("Failed to add the request")
	}

	if len(xchg.removeExpired()) > 0 {
		t.Errorf("The removeExpired method returned requests too early")
	}

	time.Sleep(1500 * time.Millisecond)
	set := stringset.New(names...)
	for _, req := range xchg.removeExpired() {
		set.Remove(req.Name)
	}

	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeExpired")
	}
}

func TestXchgRemoveAll(t *testing.T) {
	xchg := newXchgManager()
	names := []string{"caffix.net", "www.caffix.net", "blog.caffix.net"}

	QueryTimeout = time.Second
	for _, name := range names {
		msg := QueryMsg(name, dns.TypeA)
		if err := xchg.add(&resolveRequest{
			ID:    msg.Id,
			Name:  name,
			Qtype: dns.TypeA,
			Msg:   msg,
		}); err != nil {
			t.Errorf("Failed to add the request")
		}
	}

	set := stringset.New(names...)
	for _, req := range xchg.removeAll() {
		set.Remove(req.Name)
	}

	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeAll")
	}
}

func TestSlidingWindowBelowMin(t *testing.T) {
	timeouts := newSlidingWindowTimeouts()

	for i := 0; i < minNumInAverage-1; i++ {
		if timeouts.updateTimeouts("min", true) {
			t.Errorf("Reported true before reaching the minimum number of samples")
		}
	}

	if !timeouts.updateTimeouts("min", true) {
		t.Errorf("Failed to report true after reaching the minimum number of samples")
	}
}

func TestSlidingWindowFailurePercentage(t *testing.T) {
	timeouts := newSlidingWindowTimeouts()

	total := float64(maxNumInAverage)
	num := total * failurePercentage
	for i := float64(0); i < total-num; i++ {
		timeouts.updateTimeouts("per", false)
	}

	for i := float64(0); i < num-1; i++ {
		if timeouts.updateTimeouts("per", true) {
			t.Errorf("Reported true before reaching the failure percentage")
		}
	}

	if !timeouts.updateTimeouts("per", true) {
		t.Errorf("Failed to report true after reaching the failure percentage")
	}
}
