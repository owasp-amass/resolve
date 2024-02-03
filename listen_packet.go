// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package resolve

import (
	"net"
)

func (r *connections) ListenPacket() (net.PacketConn, error) {
	return net.ListenPacket("udp", ":0")
}
