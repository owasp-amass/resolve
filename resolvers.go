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
	"runtime"
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
	conns     *connections
	pool      selector
	wildcards map[string]*wildcard
	queue     queue.Queue
	resps     queue.Queue
	qps       int
	rate      *rate.Limiter
	detector  *resolver
	timeout   time.Duration
}

type resolver struct {
	done    chan struct{}
	pool    *Resolvers
	queue   queue.Queue
	xchgs   *xchgMgr
	address *net.UDPAddr
	rate    *rateTrack
}

func (r *Resolvers) initResolver(addr string) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	var res *resolver
	if uaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		res = &resolver{
			done:    make(chan struct{}, 1),
			pool:    r,
			queue:   queue.NewQueue(),
			xchgs:   newXchgMgr(r.timeout),
			address: uaddr,
			rate:    newRateTrack(),
		}
		go res.processRequests()
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
func NewResolvers() *Resolvers {
	responses := queue.NewQueue()
	r := &Resolvers{
		done:      make(chan struct{}, 1),
		log:       log.New(io.Discard, "", 0),
		conns:     newConnections(runtime.NumCPU(), responses),
		wildcards: make(map[string]*wildcard),
		queue:     queue.NewQueue(),
		resps:     responses,
		rate:      rate.NewLimiter(rate.Inf, 1),
		timeout:   DefaultTimeout,
	}

	r.pool = newAuthNSSelector(r)
	if r.pool == nil {
		r.conns.Close()
		return nil
	}

	go r.timeouts()
	go r.enforceMaxQPS()
	go r.processResponses()
	go r.updateRateLimiters()
	return r
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
	r.Lock()
	all := r.pool.AllResolvers()
	r.Unlock()

	for _, res := range all {
		select {
		case <-res.done:
		default:
			res.xchgs.setTimeout(r.timeout)
		}
	}
}

// SetMaxQPS allows a preferred maximum number of queries per second to be specified for the pool.
func (r *Resolvers) SetMaxQPS(qps int) {
	r.Lock()
	defer r.Unlock()

	if qps > 0 {
		r.qps = qps
		r.rate.SetLimit(rate.Limit(qps))
	}
}

// AddResolvers initializes and adds new resolvers to the pool of resolvers.
func (r *Resolvers) AddResolvers(addrs ...string) error {
	r.Lock()
	defer r.Unlock()

	if sel, ok := r.pool.(*authNSSelector); ok {
		sel.Close()
		r.pool = newRandomSelector()
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
		if res := r.initResolver(addr); res != nil {
			r.pool.AddResolver(res)
		}
	}
	return nil
}

// Stop will release resources for the resolver pool and all add resolvers.
func (r *Resolvers) Stop() {
	r.Lock()
	defer r.Unlock()

	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
	r.conns.Close()
	r.pool.Close()
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
loop:
	for {
		select {
		case <-r.done:
			break loop
		case <-r.queue.Signal():
			element, found := r.queue.Next()
			if !found {
				continue loop
			}

			_ = r.rate.Wait(context.TODO())
			if req, ok := element.(*request); ok {
				name := req.Msg.Question[0].Name

				r.Lock()
				res := r.pool.GetResolver(name)
				r.Unlock()

				if res != nil {
					req.Res = res
					res.queue.Append(req)
				} else {
					req.errNoResponse()
					req.release()
				}
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

func (r *Resolvers) processResponses() {
	for {
		select {
		case <-r.done:
			return
		case <-r.resps.Signal():
		}

		r.resps.Process(func(element interface{}) {
			if response, ok := element.(*resp); ok && response != nil {
				go r.processSingleResp(response)
			}
		})
	}
}

func (r *Resolvers) processSingleResp(response *resp) {
	addr, _, _ := net.SplitHostPort(response.Addr.String())

	r.Lock()
	res := r.pool.LookupResolver(addr)
	r.Unlock()

	if res == nil {
		return
	}

	msg := response.Msg
	name := msg.Question[0].Name
	if req := res.xchgs.remove(msg.Id, name); req != nil {
		req.Resp = msg
		if req.Resp.Truncated {
			go req.Res.tcpExchange(req)
		} else {
			req.Result <- req.Resp
			delta := req.RecvAt.Sub(req.SentAt)
			req.Res.rate.ReportResponseTime(delta)
			req.release()
		}
	}
}

func (r *Resolvers) updateRateLimiters() {
	t := time.NewTimer(rateUpdateInterval)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.updateAllRateLimiters()
			t.Reset(rateUpdateInterval)
		}
	}
}

func (r *Resolvers) updateAllRateLimiters() {
	r.Lock()
	all := r.pool.AllResolvers()
	r.Unlock()

	for _, res := range all {
		select {
		case <-res.done:
		default:
			res.rate.update()
		}
	}
}

func (r *Resolvers) timeouts() {
	r.Lock()
	d := r.timeout
	r.Unlock()

	t := time.NewTicker(d)
	defer t.Stop()

	for range t.C {
		select {
		case <-r.done:
			return
		default:
		}

		r.Lock()
		all := r.pool.AllResolvers()
		r.Unlock()

		for _, res := range all {
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
	}
}

func (r *resolver) processRequests() {
	for {
		select {
		case <-r.done:
			return
		case <-r.queue.Signal():
		}

		r.queue.Process(func(element interface{}) {
			if req, ok := element.(*request); ok && req != nil {
				r.rate.Take()
				r.writeReq(req)
			}
		})
	}
}

func (r *resolver) writeReq(req *request) {
	msg := req.Msg.Copy()
	req.SentAt = time.Now()

	if err := r.xchgs.add(req); err != nil {
		req.errNoResponse()
		req.release()
	}

	if err := r.pool.conns.WriteMsg(msg, r.address); err != nil {
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
