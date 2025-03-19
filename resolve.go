// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package servers

import (
	"log"
	"runtime"
	"time"

	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
)

func NewServerPool(timeout time.Duration, logger *log.Logger, addrs ...string) *pool.Pool {
	var sel selectors.Selector

	if len(addrs) == 0 {
		sel = selectors.NewAuthoritative(timeout)
	} else {
		sel = selectors.NewRandom()
		for _, addrstr := range addrs {
			sel.Add(servers.NewNameserver(addrstr, timeout))
		}
	}

	conns := conn.New(runtime.NumCPU(), sel.Lookup)
	return pool.New(0, sel, conns, logger)
}
