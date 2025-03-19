// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	"gihub.com/oswp-amass/resolve/servers"
	"gihub.com/oswp-amass/resolve/types"
	"github.com/miekg/dns"
)

var rootIPs = []string{
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

func RootServers(timeout time.Duration) []types.Nameserver {
	var servs []types.Nameserver

	for _, ip := range rootIPs {
		if serv := servers.NewNameserver(ip, timeout); serv != nil {
			servs = append(servs, serv)
		}
	}

	return servs
}

func TCPExchange(req types.Request, timeout time.Duration) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}

	if m, _, err := client.Exchange(req.Message(), req.Server().Address().String()); err == nil {
		req.ResultChan() <- m
	} else {
		req.NoResponse()
	}
	req.Release()
}
