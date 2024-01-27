// Copyright © by Jeff Foley 2022-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"testing"
)

func TestClientSubnetCheck(t *testing.T) {
	r := NewResolvers()
	_ = r.AddResolvers(10, "8.8.8.8")
	defer r.Stop()

	r.ClientSubnetCheck()
	if r.Len() == 0 {
		t.Errorf("the client subnet check failed")
	}
}
