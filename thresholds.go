// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ThresholdOptions struct {
	ThresholdValue         uint64
	CumulativeAccumulation bool // instead of continuous
	CountTimeouts          bool
	CountFormatErrors      bool
	CountServerFailures    bool
	CountNotImplemented    bool
	CountQueryRefusals     bool
}

type stats struct {
	sync.Mutex
	LastSuccess         uint64
	CountTimeouts       bool
	Timeouts            uint64
	CountFormatErrors   bool
	FormatErrors        uint64
	CountServerFailures bool
	ServerFailures      uint64
	CountNotImplemented bool
	NotImplemented      uint64
	CountQueryRefusals  bool
	QueryRefusals       uint64
}

// SetThresholdOptions updates the settings used for discontinuing use of a resolver due to poor performance.
func (r *Resolvers) SetThresholdOptions(opt *ThresholdOptions) {
	r.Lock()
	defer r.Unlock()

	r.options = opt
	r.updateThresholdOptions()
}

func (r *Resolvers) updateThresholdOptions() {
	for _, res := range r.list {
		select {
		case <-res.done:
		default:
			res.stats.Lock()
			res.stats.CountTimeouts = r.options.CountTimeouts
			res.stats.CountFormatErrors = r.options.CountFormatErrors
			res.stats.CountServerFailures = r.options.CountServerFailures
			res.stats.CountNotImplemented = r.options.CountNotImplemented
			res.stats.CountQueryRefusals = r.options.CountQueryRefusals
			res.stats.Unlock()
		}
	}
}

func (r *Resolvers) thresholdChecks() {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.shutdownIfThresholdViolated()
		}
	}
}

func (r *Resolvers) shutdownIfThresholdViolated() {
	r.Lock()
	list := r.list
	opts := *r.options
	r.Unlock()

	if opts.ThresholdValue == 0 {
		return
	}

	for idx, res := range list {
		res.stats.Lock()
		if !opts.CumulativeAccumulation {
			if res.stats.LastSuccess < opts.ThresholdValue {
				res.stats.Unlock()
				continue
			}
			r.stopResolver(idx)
		}

		var total uint64
		if opts.CountTimeouts {
			total += res.stats.Timeouts
		}
		if opts.CountFormatErrors {
			total += res.stats.FormatErrors
		}
		if opts.CountServerFailures {
			total += res.stats.ServerFailures
		}
		if opts.CountNotImplemented {
			total += res.stats.FormatErrors
		}
		if opts.CountQueryRefusals {
			total += res.stats.FormatErrors
		}
		if total >= opts.ThresholdValue {
			r.stopResolver(idx)
		}
		res.stats.Unlock()
	}
}

func (r *resolver) collectStats(resp *dns.Msg) {
	r.stats.Lock()
	defer r.stats.Unlock()

	if resp == nil {
		return
	}

	var incLastSuccess bool
	switch resp.Rcode {
	case RcodeNoResponse:
		r.stats.Timeouts++
		if r.stats.CountTimeouts {
			incLastSuccess = true
		}
	case dns.RcodeFormatError:
		r.stats.FormatErrors++
		if r.stats.CountFormatErrors {
			incLastSuccess = true
		}
	case dns.RcodeServerFailure:
		r.stats.ServerFailures++
		if r.stats.CountServerFailures {
			incLastSuccess = true
		}
	case dns.RcodeNotImplemented:
		r.stats.NotImplemented++
		if r.stats.CountNotImplemented {
			incLastSuccess = true
		}
	case dns.RcodeRefused:
		r.stats.QueryRefusals++
		if r.stats.CountQueryRefusals {
			incLastSuccess = true
		}
	default:
		r.stats.LastSuccess = 0
	}

	if incLastSuccess {
		r.stats.LastSuccess++
	}
}
