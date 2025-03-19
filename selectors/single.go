// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package selectors

import (
	"github.com/owasp-amass/resolve/types"
)

func NewSingle(serv types.Nameserver) *single {
	return &single{server: serv}
}

func (r *single) Get(fqdn string) types.Nameserver    { return r.server }
func (r *single) Lookup(addr string) types.Nameserver { return r.server }
func (r *single) Add(ns types.Nameserver)             {}
func (r *single) Remove(ns types.Nameserver)          {}
func (r *single) All() []types.Nameserver             { return []types.Nameserver{r.server} }
func (r *single) Close()                              { r.server = nil }
