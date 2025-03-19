// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"

	"github.com/miekg/dns"
)

type Conn interface {
	Close()
	WriteMsg(msg *dns.Msg, addr net.Addr) error
}
