// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// Resolvers is a pool of DNS resolvers managed for brute forcing using random selection.
type Resolvers struct {
	sync.Mutex
	done      chan struct{}
	log       *log.Logger
	conns     *ConnPool
	pool      Selector
	wildcards map[string]*wildcard
	queue     queue.Queue
	rate      *rate.Limiter
	detector  *resolver
	timeout   time.Duration
}

type resolver struct {
	done    chan struct{}
	xchgs   *xchgMgr
	address *net.UDPAddr
	rate    *rateTrack
}

func NewResolver(addr string, timeout time.Duration) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	var res *resolver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		res = &resolver{
			done:    make(chan struct{}, 1),
			xchgs:   newXchgMgr(timeout),
			address: uaddr,
			rate:    newRateTrack(),
		}
	}
	return res
}

func (r *resolver) stop() {
	select {
	case <-r.done:
		return
	default:
	}
	// Send the signal to shutdown and close the connection
	close(r.done)
	// Drain the xchgs of all messages and allow callers to return
	for _, req := range r.xchgs.removeAll() {
		req.errNoResponse()
		req.release()
	}
}

// NewResolvers initializes a Resolvers.
func NewResolvers(qps int, timeout time.Duration, sel Selector, conns *ConnPool) *Resolvers {
	limit := rate.Inf
	if qps > 0 {
		limit = rate.Limit(qps)
	}

	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	r := &Resolvers{
		done:      make(chan struct{}, 1),
		log:       log.New(io.Discard, "", 0),
		conns:     conns,
		pool:      sel,
		wildcards: make(map[string]*wildcard),
		queue:     queue.NewQueue(),
		rate:      rate.NewLimiter(limit, 1),
		timeout:   timeout,
	}

	go r.timeouts()
	go r.enforceMaxQPS()
	return r
}

// AddResolvers initializes and adds new resolvers to the pool of resolvers.
func (r *Resolvers) AddResolvers(addrs ...string) error {
	if _, ok := r.pool.(*authNSSelector); ok {
		return nil
	}

	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// add the default port number to the IP address
			addr = net.JoinHostPort(addr, "53")
		}
		// check that this address will not create a duplicate resolver
		if res := r.pool.LookupResolver(addr); res != nil {
			continue
		}
		if res := NewResolver(addr, r.timeout); res != nil {
			r.pool.AddResolver(res)
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
	default:
		if req := reqPool.Get().(*request); req != nil {
			req.Msg = msg
			req.Result = ch
			r.queue.Append(req)
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

	var err error
	ch := r.QueryChan(ctx, msg)
	defer close(ch)

	resp := <-ch
	if resp == nil {
		err = errors.New("query failed")
	}
	return resp, err
}

func (r *Resolvers) enforceMaxQPS() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-r.done:
			break loop
		case <-t.C:
		case <-r.queue.Signal():
		}

		if element, found := r.queue.Next(); found {
			if req, ok := element.(*request); ok {
				_ = r.rate.Wait(context.TODO())
				go r.processSingleReq(req)
			}
		}
	}
	// release the requests remaining on the queue
	r.queue.Process(func(element interface{}) {
		if req, ok := element.(request); ok {
			req.errNoResponse()
			req.release()
		}
	})
}

func (r *Resolvers) processSingleReq(req *request) {
	name := req.Msg.Question[0].Name

	if res := r.pool.GetResolver(name); res != nil {
		req.Res = res
		res.sendRequest(req, r.conns)
		return
	}

	req.errNoResponse()
	req.release()
}

func (r *Resolvers) timeouts() {
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

func (r *resolver) sendRequest(req *request, conns *ConnPool) {
	if req == nil {
		return
	}

	select {
	case <-r.done:
		req.errNoResponse()
		req.release()
		return
	default:
	}

	r.rate.Take()
	r.writeReq(req, conns)
}

func (r *resolver) writeReq(req *request, conns *ConnPool) {
	if conns == nil {
		req.errNoResponse()
		req.release()
		return
	}

	msg := req.Msg.Copy()
	req.SentAt = time.Now()

	if err := r.xchgs.add(req); err != nil {
		req.errNoResponse()
		req.release()
	}

	if err := conns.WriteMsg(msg, r.address); err != nil {
		_ = r.xchgs.remove(msg.Id, msg.Question[0].Name)
		req.errNoResponse()
		req.release()
	}
}

func (r *resolver) tcpExchange(req *request) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: 5 * time.Second,
	}

	if m, _, err := client.Exchange(req.Msg, r.address.String()); err == nil {
		req.Result <- m
	} else {
		req.errNoResponse()
	}
	req.release()
}
