// Copyright © by Jeff Foley 2017-2022. All rights reserved.
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
	"go.uber.org/ratelimit"
)

const headerSize = 12

// Resolvers is a pool of DNS resolvers managed for brute forcing using random selection.
type Resolvers struct {
	sync.Mutex
	done      chan struct{}
	log       *log.Logger
	conns     *connections
	pool      selector
	rmap      map[string]struct{}
	wildcards map[string]*wildcard
	queue     queue.Queue
	resps     queue.Queue
	qps       int
	maxSet    bool
	rate      ratelimit.Limiter
	servRates *serversRateLimiter
	detector  *resolver
	timeout   time.Duration
	options   *ThresholdOptions
}

type resolver struct {
	done    chan struct{}
	xchgs   *xchgMgr
	address *net.UDPAddr
	qps     int
	stats   *stats
}

func (r *Resolvers) initializeResolver(addr string, qps int) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}

	return &resolver{
		done:    make(chan struct{}, 1),
		xchgs:   newXchgMgr(r.timeout),
		address: uaddr,
		qps:     qps,
		stats:   new(stats),
	}
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
		pool:      newRandomSelector(),
		rmap:      make(map[string]struct{}),
		wildcards: make(map[string]*wildcard),
		queue:     queue.NewQueue(),
		resps:     responses,
		servRates: newServersRateLimiter(),
		timeout:   DefaultTimeout,
		options:   new(ThresholdOptions),
	}

	go r.processResponses()
	go r.timeouts()
	go r.enforceMaxQPS()
	go r.thresholdChecks()
	return r
}

// Len returns the number of resolvers that have been added to the pool.
func (r *Resolvers) Len() int {
	return r.pool.Len()
}

// SetLogger assigns a new logger to the resolver pool.
func (r *Resolvers) SetLogger(l *log.Logger) {
	r.log = l
}

// SetTimeout updates the amount of time this pool will wait for response messages.
func (r *Resolvers) SetTimeout(d time.Duration) {
	r.Lock()
	defer r.Unlock()

	r.timeout = d
	r.updateResolverTimeouts()
}

func (r *Resolvers) updateResolverTimeouts() {
	all := r.pool.AllResolvers()
	if r.detector != nil {
		all = append(all, r.detector)
	}

	for _, res := range all {
		select {
		case <-res.done:
		default:
			res.xchgs.setTimeout(r.timeout)
		}
	}
}

// QPS returns the maximum queries per second provided by the resolver pool.
func (r *Resolvers) QPS() int {
	r.Lock()
	defer r.Unlock()

	return r.qps
}

// SetMaxQPS allows a preferred maximum number of queries per second to be specified for the pool.
func (r *Resolvers) SetMaxQPS(qps int) {
	r.qps = qps
	if qps > 0 {
		r.maxSet = true
		r.rate = ratelimit.New(qps)
		return
	}
	r.maxSet = false
	r.rate = nil
}

// AddResolvers initializes and adds new resolvers to the pool of resolvers.
func (r *Resolvers) AddResolvers(qps int, addrs ...string) error {
	r.Lock()
	defer r.Unlock()

	if qps == 0 {
		return errors.New("failed to provide a maximum number of queries per second greater than zero")
	}

	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// add the default port number to the IP address
			addr = net.JoinHostPort(addr, "53")
		}
		// check that this address will not create a duplicate resolver
		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			continue
		}
		if _, found := r.rmap[uaddr.IP.String()]; found {
			continue
		}
		if res := r.initializeResolver(addr, qps); res != nil {
			r.rmap[res.address.IP.String()] = struct{}{}
			r.pool.AddResolver(res)
			if !r.maxSet {
				r.qps += qps
			}
		}
	}
	// create the new rate limiter for the updated QPS
	if !r.maxSet {
		r.rate = ratelimit.New(r.qps)
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
	r.conns.Close()

	all := r.pool.AllResolvers()
	if d := r.getDetectionResolver(); d != nil {
		all = append(all, d)
	}

	for _, res := range all {
		if !r.maxSet {
			r.qps -= res.qps
		}
		res.stop()
	}
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
		req := reqPool.Get().(*request)

		req.Msg = msg
		req.Result = ch
		r.servRates.Take(RemoveLastDot(msg.Question[0].Name))
		r.queue.Append(req)
		return
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

func (r *Resolvers) enforceMaxQPS() {
loop:
	for {
		select {
		case <-r.done:
			break loop
		case <-r.queue.Signal():
			if r.rate != nil {
				r.rate.Take()
			}
			e, ok := r.queue.Next()
			if !ok {
				continue loop
			}
			if req, ok := e.(*request); ok {
				if res := r.pool.GetResolver(); res != nil {
					req.Res = res
					r.writeMsg(req)
					continue loop
				}
				req.errNoResponse()
				req.release()
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

		var response *resp
		if element, ok := r.resps.Next(); ok {
			if r, valid := element.(*resp); valid {
				response = r
			}
		}
		if response == nil {
			continue
		}

		var res *resolver
		addr := response.Addr.IP.String()
		if res = r.pool.LookupResolver(addr); res == nil {
			detector := r.getDetectionResolver()

			if addr == detector.address.IP.String() {
				res = detector
			}
		}
		if res == nil {
			continue
		}

		msg := response.Msg
		if req := res.xchgs.remove(msg.Id, msg.Question[0].Name); req != nil {
			req.Resp = msg
			if req.Resp.Truncated {
				go req.Res.tcpExchange(req)
			} else {
				req.Result <- req.Resp
				req.Res.collectStats(req.Resp)
				req.release()
			}
		}
	}
}

func (r *Resolvers) timeouts() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		all := r.pool.AllResolvers()
		if d := r.getDetectionResolver(); d != nil {
			all = append(all, d)
		}

		for _, res := range all {
			select {
			case <-r.done:
				return
			default:
				for _, req := range res.xchgs.removeExpired() {
					req.errNoResponse()
					res.collectStats(req.Msg)
					req.release()
				}
			}
		}
		// wait a bit before checking again
		r.Lock()
		d := r.timeout / 2
		r.Unlock()
		time.Sleep(d)
	}
}

func (r *Resolvers) writeMsg(req *request) {
	res := req.Res

	out, err := req.Msg.Pack()
	if err != nil {
		return
	}

	now := time.Now()
	// Set the timestamp for message expiration
	req.Timestamp = now
	if res.xchgs.add(req) != nil {
		return
	}

	conn := r.conns.Next()
	conn.SetWriteDeadline(now.Add(500 * time.Millisecond))
	if n, err := conn.WriteToUDP(out, res.address); err != nil || n < len(out) {
		_ = res.xchgs.remove(req.Msg.Id, req.Msg.Question[0].Name)
		req.errNoResponse()
		req.release()
	}
}

func (r *resolver) tcpExchange(req *request) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: time.Minute,
	}
	if m, _, err := client.Exchange(req.Msg, r.address.String()); err == nil {
		req.Result <- m
		r.collectStats(m)
	} else {
		req.errNoResponse()
	}
	req.release()
}
