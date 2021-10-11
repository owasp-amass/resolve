// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolve

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const queriesPerSort int = 125

type resolverPool struct {
	sync.Mutex
	done chan struct{}
	// Logger for error messages
	log            *log.Logger
	baseline       Resolver
	partitions     [][]Resolver
	cur            int
	sorted         []Resolver
	queryCount     int
	last           time.Time
	hasBeenStopped bool
}

// NewResolverPool initializes a ResolverPool that uses the provided Resolvers.
func NewResolverPool(resolvers []Resolver, baseline Resolver, partnum int, logger *log.Logger) Resolver {
	l := len(resolvers)
	if l == 0 {
		return nil
	}
	if partnum <= 0 {
		partnum = 1
	}
	if l < partnum {
		partnum = l
	}

	rp := &resolverPool{
		baseline:   baseline,
		partitions: make([][]Resolver, partnum),
		queryCount: queriesPerSort,
		last:       time.Now(),
		done:       make(chan struct{}, 2),
		log:        logger,
	}

	num := l / partnum
	for i := 0; i < partnum; i++ {
		start := i * num
		end := (start + num) - 1

		if i == partnum-1 {
			rp.partitions[i] = resolvers[start:]
		} else {
			rp.partitions[i] = resolvers[start:end]
		}
	}

	// Assign a null logger when one is not provided
	if rp.log == nil {
		rp.log = log.New(ioutil.Discard, "", 0)
	}

	return rp
}

// Len implements the Resolver interface.
func (rp *resolverPool) Len() int {
	var total int
	if rp.baseline != nil {
		total += rp.baseline.Len()
	}

	for _, part := range rp.partitions {
		for _, r := range part {
			total += r.Len()
		}
	}

	return total
}

// Stop implements the Resolver interface.
func (rp *resolverPool) Stop() {
	if rp.hasBeenStopped {
		return
	}
	rp.hasBeenStopped = true
	close(rp.done)

	for _, partition := range rp.partitions {
		for _, r := range partition {
			r.Stop()
		}
	}

	if rp.baseline != nil {
		rp.baseline.Stop()
	}

	rp.partitions = [][]Resolver{}
}

// Stopped implements the Resolver interface.
func (rp *resolverPool) Stopped() bool {
	return rp.hasBeenStopped
}

// String implements the Stringer interface.
func (rp *resolverPool) String() string {
	return "ResolverPool"
}

func (rp *resolverPool) nextPartition() {
	rp.Lock()
	defer rp.Unlock()

	if time.Now().Before(rp.last.Add(30 * time.Second)) {
		return
	}

	rp.cur++
	rp.cur = rp.cur % len(rp.partitions)
	rp.last = time.Now()
	rp.queryCount = queriesPerSort

	if len(rp.partitions[rp.cur]) == 0 {
		rp.checkPartitions()
	}
}

func (rp *resolverPool) checkPartitions() {
	var parts [][]Resolver
	plen := len(rp.partitions)

	var i int
	for _, p := range rp.partitions {
		if len(p) > 0 {
			parts[i] = p
			i++
		}
	}

	rp.partitions = parts
	if len(parts) < plen {
		rp.cur = 0
	}
}

func (rp *resolverPool) numUsableResolvers() int {
	var num int
	for _, partition := range rp.partitions {
		for _, r := range partition {
			if !r.Stopped() {
				num++
			}
		}
	}
	return num
}

func (rp *resolverPool) getSortedPartition() []Resolver {
	rp.Lock()
	defer rp.Unlock()

	if rp.resort() {
		rp.sorted = rp.copyAndSort()
	}
	return rp.sorted
}

func (rp *resolverPool) resort() bool {
	result := rp.queryCount >= queriesPerSort
	if result {
		rp.queryCount = 0
	}
	return result
}

func (rp *resolverPool) incQueryCount() {
	rp.Lock()
	defer rp.Unlock()

	rp.queryCount++
}

func (rp *resolverPool) copyAndSort() []Resolver {
	var part []Resolver
	for _, r := range rp.partitions[rp.cur] {
		if !r.Stopped() {
			part = append(part, r)
		}
	}

	sort.Slice(part, func(i, j int) bool {
		return part[i].Len() < part[j].Len()
	})
	return part
}

// Query implements the Resolver interface.
func (rp *resolverPool) Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error) {
	if rp.baseline != nil && rp.numUsableResolvers() == 0 {
		return rp.baseline.Query(ctx, msg, priority, retry)
	}

	var err error
	var r Resolver
	var resp *dns.Msg
	rp.nextPartition()
	part := rp.getSortedPartition()
	for times := 1; !attemptsExceeded(times-1, priority); times++ {
		err = checkContext(ctx)
		if err != nil {
			break
		}

		for i := 0; i < len(part); i++ {
			idx := ((times - 1) + i) % len(part)

			if res := part[idx]; !res.Stopped() {
				r = res
				break
			}
		}
		if r == nil {
			err = errors.New("failed to obtain a resolver")
			break
		}

		rp.incQueryCount()
		resp, err = r.Query(ctx, msg, priority, nil)
		if err == nil {
			break
		}
		// Timeouts and resolver errors can cause retries without executing the callback
		if e, ok := err.(*ResolveError); ok && (e.Rcode == TimeoutRcode || e.Rcode == ResolverErrRcode) {
			continue
		}
		if retry == nil || !retry(times, priority, resp) {
			break
		}
	}

	if rp.baseline != nil && err == nil && len(resp.Answer) > 0 {
		// Validate findings from an untrusted resolver
		resp, err = rp.baseline.Query(ctx, msg, priority, retry)
		// False positives result in stopping the untrusted resolver
		if err == nil && resp != nil && len(resp.Answer) == 0 {
			r.Stop()
		}
	}
	return resp, err
}

// WildcardType implements the Resolver interface.
func (rp *resolverPool) WildcardType(ctx context.Context, msg *dns.Msg, domain string) int {
	wtype := rp.partitions[0][0].WildcardType

	if rp.baseline != nil {
		wtype = rp.baseline.WildcardType
	}

	return wtype(ctx, msg, domain)
}
