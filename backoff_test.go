// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"testing"
	"time"
)

func TestExponentialBackoff(t *testing.T) {
	tests := []struct {
		name     string
		events   int
		delay    time.Duration
		expected time.Duration
	}{
		{
			name:     "Two events and 500ms delay",
			events:   2,
			delay:    500 * time.Millisecond,
			expected: 2 * time.Second,
		},
		{
			name:     "Four events and 1sec delay",
			events:   4,
			delay:    time.Second,
			expected: 16 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := ExponentialBackoff(tt.events, tt.delay)

			if backoff < tt.expected || backoff > tt.expected+tt.delay {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, backoff)
			}
		})
	}
}

func TestTruncatedExponentialBackoff(t *testing.T) {
	tests := []struct {
		name     string
		events   int
		delay    time.Duration
		max      time.Duration
		expected time.Duration
	}{
		{
			name:     "One event and 250ms delay with 2sec max",
			events:   1,
			delay:    250 * time.Millisecond,
			max:      2 * time.Second,
			expected: 500 * time.Millisecond,
		},
		{
			name:     "Four events and 500ms delay with 4sec max",
			events:   4,
			delay:    500 * time.Millisecond,
			max:      4 * time.Second,
			expected: 4 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := TruncatedExponentialBackoff(tt.events, tt.delay, tt.max)

			if backoff < tt.expected || backoff > tt.expected+tt.delay {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, backoff)
			}
		})
	}
}

func TestBackoffJitter(t *testing.T) {
	tests := []struct {
		name string
		min  time.Duration
		max  time.Duration
	}{
		{
			name: "The max is less than the min",
			min:  time.Second,
			max:  500 * time.Millisecond,
		},
		{
			name: "Between one and four seconds",
			min:  time.Second,
			max:  4 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := BackoffJitter(tt.min, tt.max)

			if tt.min >= tt.max {
				if backoff != time.Duration(0) {
					t.Errorf("Unexpected Result, expected %v, got %v", 0, backoff)
				}
				return
			}
			if backoff < tt.min || backoff > tt.max {
				t.Errorf("Unexpected Result from min: %v, max: %v, got %v", tt.min, tt.max, backoff)
			}
		})
	}
}
