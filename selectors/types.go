// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"sync"
	"time"

	"github.com/owasp-amass/resolve/types"
)

type single struct {
	done    chan struct{}
	timeout time.Duration
	server  types.Nameserver
}

type random struct {
	sync.Mutex
	done    chan struct{}
	timeout time.Duration
	list    []types.Nameserver
	lookup  map[string]types.Nameserver
}

type authoritative struct {
	sync.Mutex
	done          chan struct{}
	timeout       time.Duration
	newserver     NewServer
	list          []types.Nameserver
	lookup        map[string]types.Nameserver
	roots         []types.Nameserver
	fqdnToServers map[string][]string
	fqdnToNSs     map[string][]types.Nameserver
	serverToNSs   map[string]types.Nameserver
}
