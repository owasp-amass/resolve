// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wildcards

import (
	"math/rand"
	"strings"
)

// Constants related to DNS labels.
const (
	MaxDNSNameLen  = 253
	MaxDNSLabelLen = 63
	MinLabelLen    = 6
	MaxLabelLen    = 24
	LDHChars       = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain.
func UnlikelyName(sub string) string {
	ldh := []rune(LDHChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := MaxDNSNameLen - (len(sub) + 1)
	if l > MaxLabelLen {
		l = MaxLabelLen
	} else if l < MinLabelLen {
		l = MinLabelLen
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	var newlabel string
	l = MinLabelLen + rand.Intn((l-MinLabelLen)+1)
	for i := 0; i < l; i++ {
		sel := rand.Int() % (ldhLen - 1)
		newlabel = newlabel + string(ldh[sel])
	}

	newlabel = strings.Trim(newlabel, "-")
	if newlabel == "" {
		return newlabel
	}
	return newlabel + "." + sub
}
