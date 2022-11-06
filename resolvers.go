// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolvers is a pool of DNS resolvers managed for brute forcing using random selection.
type Resolvers struct {
	sync.Mutex
	done      chan struct{}
	ticker    *time.Ticker
	log       *log.Logger
	servers   selector
	wildcards map[string]*wildcard
	detector  *resolver
	timeout   time.Duration
}

// NewResolvers initializes a Resolvers that operates at the provide number of queries per second.
func NewResolvers(qps int) *Resolvers {
	if qps <= 0 {
		return nil
	}

	return &Resolvers{
		done:      make(chan struct{}, 1),
		ticker:    time.NewTicker(time.Second / time.Duration(qps)),
		log:       log.New(io.Discard, "", 0),
		servers:   newRandomSelector(),
		wildcards: make(map[string]*wildcard),
		timeout:   DefaultTimeout,
	}
}

// Len returns the number of resolvers that have been added to the pool.
func (r *Resolvers) Len() int {
	return r.servers.Len()
}

// SetLogger assigns a new logger to the resolver pool.
func (r *Resolvers) SetLogger(l *log.Logger) {
	r.log = l
}

// SetTimeout updates the amount of time this pool will wait for response messages.
func (r *Resolvers) SetTimeout(d time.Duration) {
	r.Lock()
	r.timeout = d
	r.Unlock()

	r.updateResolverTimeouts()
}

func (r *Resolvers) updateResolverTimeouts() {
	for _, res := range r.servers.AllResolvers() {
		res.timeout = r.timeout
	}
}

// AddResolvers initializes and adds new resolvers to the pool of resolvers.
func (r *Resolvers) AddResolvers(addrs ...string) error {
	for _, addr := range addrs {
		if err := r.servers.AddResolver(addr, r.timeout); err != nil {
			return err
		}
	}
	return nil
}

// Stop will release resources for the resolver pool and all add resolvers.
func (r *Resolvers) Stop() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)

	r.ticker.Stop()
	r.servers.Close()
}

// Query queues the provided DNS message and returns the response on the provided channel.
func (r *Resolvers) Query(ctx context.Context, msg *dns.Msg, ch chan *dns.Msg) {
	if msg == nil {
		ch <- msg
		return
	}

	select {
	case <-ctx.Done():
	case <-r.done:
	case <-r.ticker.C:
		req := reqPool.Get().(*request)

		req.Ctx = ctx
		req.ID = msg.Id
		req.Name = RemoveLastDot(msg.Question[0].Name)
		req.Qtype = msg.Question[0].Qtype
		req.Msg = msg
		req.Result = ch

		if res := r.servers.GetResolver(req.Name); res != nil {
			res.exchange(req)
			return
		}
	}

	msg.Rcode = RcodeNoResponse
	ch <- msg
}

// Query queues the provided DNS message and sends the response on the returned channel.
func (r *Resolvers) QueryChan(ctx context.Context, msg *dns.Msg) chan *dns.Msg {
	ch := make(chan *dns.Msg, 1)
	r.Query(ctx, msg, ch)
	return ch
}

// Query queues the provided DNS message and returns the associated response message.
func (r *Resolvers) QueryBlocking(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	select {
	case <-ctx.Done():
		return msg, errors.New("the context expired")
	default:
	}

	ch := r.QueryChan(ctx, msg)

	select {
	case <-ctx.Done():
		return msg, errors.New("the context expired")
	case resp := <-ch:
		var err error
		if resp == nil {
			err = errors.New("query failed")
		}
		return resp, err
	}
}
