// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	"golang.org/x/time/rate"
)

// Pool is a managed pool of DNS nameservers.
type Pool struct {
	sync.Mutex
	done      chan struct{}
	log       *log.Logger
	conns     *ConnPool
	pool      Selector
	wildcards map[string]*wildcard
	rate      *rate.Limiter
	detector  *Nameserver
	timeout   time.Duration
}

// NewPool initializes a DNS nameserver pool.
func NewPool(qps int, timeout time.Duration, sel Selector, conns *ConnPool) *Pool {
	limit := rate.Inf
	if qps > 0 {
		limit = rate.Limit(qps)
	}

	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	p := &Pool{
		done:      make(chan struct{}, 1),
		log:       log.New(io.Discard, "", 0),
		conns:     conns,
		pool:      sel,
		wildcards: make(map[string]*wildcard),
		rate:      rate.NewLimiter(limit, 1),
		timeout:   timeout,
	}

	go p.timeouts()
	return p
}

// Stop will release resources use by the pool.
func (r *Pool) Stop() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
}

// Query sends the DNS message and returns the response on the provided channel.
func (r *Pool) Query(ctx context.Context, msg *dns.Msg, ch chan *dns.Msg) {
	if msg == nil {
		ch <- msg
		return
	}

	select {
	case <-ctx.Done():
	case <-r.done:
	default:
		if req := reqPool.Get().(*request); req != nil {
			req.Msg = msg
			req.Result = ch
			go r.processSingleReq(req)
			return
		}
	}

	msg.Rcode = RcodeNoResponse
	ch <- msg
}

// QueryChan sends the provided DNS message and the response is provided on the returned channel.
// The channel is buffered to prevent blocking.
func (r *Pool) QueryChan(ctx context.Context, msg *dns.Msg) chan *dns.Msg {
	ch := make(chan *dns.Msg, 1)
	r.Query(ctx, msg, ch)
	return ch
}

// Exchange sends the DNS message and returns the response message.
func (r *Pool) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	select {
	case <-ctx.Done():
		return msg, errors.New("the context expired")
	default:
	}

	var err error
	ch := r.QueryChan(ctx, msg)
	defer close(ch)

	resp := <-ch
	if resp == nil {
		err = errors.New("query failed")
	}
	return resp, err
}

func (r *Pool) processSingleReq(req *request) {
	name := req.Msg.Question[0].Name

	if res := r.pool.GetResolver(name); res != nil {
		req.Res = res
		_ = r.rate.Wait(context.TODO())
		res.sendRequest(req, r.conns)
		return
	}

	req.errNoResponse()
	req.release()
}

func (r *Pool) timeouts() {
	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for range t.C {
		select {
		case <-r.done:
			return
		default:
		}

		for _, res := range r.pool.AllResolvers() {
			select {
			case <-r.done:
				return
			default:
				for _, req := range res.xchgs.removeExpired() {
					req.errNoResponse()
					req.release()
				}
			}
		}

		t.Reset(r.timeout)
	}
}
