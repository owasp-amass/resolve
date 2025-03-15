// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"testing"

	"github.com/caffix/stringset"
)

func TestGetTLDServers(t *testing.T) {
	wanted := stringset.New(
		"a.edu-servers.net",
		"b.edu-servers.net",
		"c.edu-servers.net",
		"d.edu-servers.net",
		"e.edu-servers.net",
		"f.edu-servers.net",
		"g.edu-servers.net",
		"h.edu-servers.net",
		"i.edu-servers.net",
		"j.edu-servers.net",
		"k.edu-servers.net",
		"l.edu-servers.net",
		"m.edu-servers.net",
	)

	servers := getTLDServers("edu")
	if servers == nil {
		t.Errorf("Failed to obtain the .edu servers")
		return
	}
	got := stringset.New(servers...)

	wanted.Subtract(got)
	if wanted.Len() > 0 {
		t.Errorf("Failed to obtain the .edu servers")
	}
}
