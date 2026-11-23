// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
)

// stubServer is a nameserver that only records whether it was closed.
type stubServer struct {
	addr   *net.UDPAddr
	closed bool
}

func newStubServer(ip string) *stubServer {
	return &stubServer{addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 53}}
}

func (s *stubServer) Address() *net.UDPAddr               { return s.addr }
func (s *stubServer) XchgManager() types.XchgManager      { return nil }
func (s *stubServer) RateMonitor() types.RateTrack        { return nil }
func (s *stubServer) RequestResponse(*dns.Msg, time.Time) {}
func (s *stubServer) Close()                              { s.closed = true }

func (s *stubServer) SendRequest(context.Context, types.Request, types.Conn) error { return nil }

func (s *stubServer) NsecTraversal(context.Context, string, types.Conn) ([]*dns.NSEC, error) {
	return nil, nil
}

func TestRoundRobinRotatesAndLooksUp(t *testing.T) {
	a, b := newStubServer("192.0.2.1"), newStubServer("192.0.2.2")
	r := NewSharedRoundRobin(a, b)
	defer r.Close()

	seen := make(map[types.Nameserver]int)
	for i := 0; i < 4; i++ {
		ns, err := r.Get("example.com")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		seen[ns]++
	}
	if seen[a] != 2 || seen[b] != 2 {
		t.Errorf("the selector did not take turns: %d and %d", seen[a], seen[b])
	}
	if ns, err := r.Lookup("192.0.2.2"); err != nil || ns != b {
		t.Errorf("Lookup(192.0.2.2) = %v, %v", ns, err)
	}
	if NewSharedRoundRobin() != nil {
		t.Error("a selector was built with no nameservers")
	}
}

func TestRoundRobinCloseClosesOnlyOwnedServers(t *testing.T) {
	owned := newStubServer("192.0.2.1")
	NewRoundRobin(time.Hour, owned).Close()
	if !owned.closed {
		t.Error("closing the selector left its own nameserver open")
	}

	shared := newStubServer("192.0.2.2")
	r := NewSharedRoundRobin(shared)
	r.Close()
	if shared.closed {
		t.Error("closing a shared selector closed the nameserver")
	}
	if _, err := r.Get("example.com"); err == nil {
		t.Error("a closed selector handed out a nameserver")
	}
}
