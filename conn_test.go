// Copyright © by Jeff Foley 2022-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
)

func TestConnections(t *testing.T) {
	name := "caffix.net."
	dns.HandleFunc(name, typeAHandler)
	defer dns.HandleRemove(name)

	s, addrstr, _, err := RunLocalUDPServer("localhost:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	resps := queue.NewQueue()
	conn := newConnections(runtime.NumCPU(), resps)
	defer conn.Close()

	for i := 0; i < 100; i++ {
		msg := QueryMsg(name, 1)

		if addr, err := net.ResolveUDPAddr("udp", addrstr); err == nil {
			_ = conn.WriteMsg(msg, addr)
		}
		if i%10 == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	timer := time.NewTimer(time.Second)
	defer timer.Stop()

	var num int
loop:
	for i := 0; i < 100; i++ {
		select {
		case <-timer.C:
			break loop
		case <-resps.Signal():
			num++
		}
	}

	if percent := float64(num) / 100; percent < 0.95 {
		t.Errorf("received only %f%% of the DNS responses", percent)
	}
}
