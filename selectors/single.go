// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"time"

	"github.com/owasp-amass/resolve/types"
)

func NewSingle(timeout time.Duration, serv types.Nameserver) *single {
	r := &single{
		done:    make(chan struct{}, 1),
		timeout: timeout,
		server:  serv,
	}

	go r.timeouts()
	return r
}

func (r *single) Get(fqdn string) (types.Nameserver, error)    { return r.server, nil }
func (r *single) Lookup(addr string) (types.Nameserver, error) { return r.server, nil }
func (r *single) All() []types.Nameserver                      { return []types.Nameserver{r.server} }

func (r *single) Close() {
	close(r.done)
	r.server.Close()
	r.server = nil
}

func (r *single) timeouts() {
	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}

		for _, req := range r.server.XchgManager().RemoveExpired(r.timeout) {
			go func(req types.Request) {
				req.NoResponse()
				req.Release()
			}(req)
		}

		t.Reset(r.timeout)
	}
}
