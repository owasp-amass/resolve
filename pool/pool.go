// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"context"
	"errors"
	"io"
	"log"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/types"
	"golang.org/x/time/rate"
)

// Pool is a managed pool of DNS nameservers.
type Pool struct {
	done     chan struct{}
	log      *log.Logger
	Conns    types.Conn
	Selector types.Selector
	rate     *rate.Limiter
}

// New initializes a DNS nameserver pool.
func New(qps int, sel types.Selector, conns types.Conn, logger *log.Logger) *Pool {
	limit := rate.Inf
	if qps > 0 {
		limit = rate.Limit(qps)
	}

	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &Pool{
		done:     make(chan struct{}, 1),
		log:      logger,
		Conns:    conns,
		Selector: sel,
		rate:     rate.NewLimiter(limit, 1),
	}
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
		if req := types.RequestPool.Get().(types.Request); req != nil {
			req.SetMessage(msg)
			req.SetRespChan(ch)
			go r.processSingleReq(req)
			return
		}
	}

	msg.Rcode = types.RcodeNoResponse
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
	} else if resp.Rcode == types.RcodeNoResponse {
		err = errors.New("no response received")
	}
	return resp, err
}

func (r *Pool) processSingleReq(req types.Request) {
	name := req.Message().Question[0].Name

	if serv := r.Selector.Get(name); serv != nil {
		req.SetServer(serv)
		_ = r.rate.Wait(context.TODO())
		if err := serv.SendRequest(req, r.Conns); err == nil {
			return
		}
	}

	req.NoResponse()
	req.Release()
}
