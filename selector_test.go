// Copyright © by Jeff Foley 2022-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"testing"
)

func TestMin(t *testing.T) {
	cases := []struct {
		x    int
		y    int
		want int
	}{
		{
			x:    4,
			y:    5,
			want: 4,
		},
		{
			x:    4,
			y:    4,
			want: 4,
		},
		{
			x:    0,
			y:    4,
			want: 0,
		},
		{
			x:    1,
			y:    0,
			want: 0,
		},
		{
			x:    10,
			y:    4,
			want: 4,
		},
	}

	for _, c := range cases {
		if m := min(c.x, c.y); m != c.want {
			t.Errorf("min returned %d instead of the expected %d", m, c.want)
		}
	}
}
