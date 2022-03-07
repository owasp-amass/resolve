// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"go.uber.org/ratelimit"
)

const maxScanLen int = 10

// Resolvers is a pool of DNS resolvers managed for brute forcing using random selection.
type Resolvers struct {
	sync.Mutex
	done      chan struct{}
	log       *log.Logger
	list      []*resolver
	rmap      map[string]int
	wildcards map[string]*wildcard
	queue     queue.Queue
	qps       int
	maxSet    bool
	rate      ratelimit.Limiter
	scan      int
	detector  *resolver
}

type resolver struct {
	done      chan struct{}
	xchgQueue queue.Queue
	xchgs     *xchgMgr
	address   string
	qps       int
	inc       time.Duration
	next      time.Time
	conn      *dns.Conn
}

// NewResolvers initializes a Resolvers that starts with the provided list of DNS resolver IP addresses.
func NewResolvers() *Resolvers {
	r := &Resolvers{
		done:      make(chan struct{}, 2),
		log:       log.New(ioutil.Discard, "", 0),
		rmap:      make(map[string]int),
		wildcards: make(map[string]*wildcard),
		queue:     queue.NewQueue(),
	}

	go r.enforceMaxQPS()
	go r.sendQueries()
	return r
}

// Len returns the number of resolvers that have been added to the pool.
func (r *Resolvers) Len() int {
	r.Lock()
	defer r.Unlock()

	return len(r.list)
}

// AddLogger assigns a new logger to the resolver pool.
func (r *Resolvers) AddLogger(l *log.Logger) {
	r.log = l
}

// QPS returns the maximum queries per second provided by the resolver pool.
func (r *Resolvers) QPS() int {
	r.Lock()
	defer r.Unlock()

	return r.qps
}

// AddMaxQPS allows a preferred maximum number of queries per second to be specified for the pool.
func (r *Resolvers) AddMaxQPS(qps int) {
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
		if res := r.initializeResolver(addr, qps); res != nil {
			r.rmap[res.address] = len(r.list)
			r.list = append(r.list, res)
			if !r.maxSet {
				r.qps += qps
			}
		}
	}
	if l := len(r.list); l > 0 {
		r.scan = min(l, maxScanLen)
	}
	return nil
}

// Stop will release resources for the resolver pool and all add resolvers.
func (r *Resolvers) Stop() {
	r.Lock()
	list := r.list
	r.Unlock()

	select {
	case <-r.done:
		return
	default:
	}

	close(r.done)
	for i := 0; i < len(list); i++ {
		r.stopResolver(i)
	}
}

// Query queues the provided DNS message and returns the response on the provided channel.
func (r *Resolvers) Query(ctx context.Context, msg *dns.Msg, ch chan *dns.Msg) {
	select {
	case <-ctx.Done():
	case <-r.done:
	default:
		r.queue.Append(&request{
			Ctx:    ctx,
			ID:     msg.Id,
			Name:   RemoveLastDot(msg.Question[0].Name),
			Qtype:  msg.Question[0].Qtype,
			Msg:    msg,
			Result: ch,
		})
		return
	}

	msg.Rcode = RcodeNoResponse
	ch <- msg
}

// Query queues the provided DNS message and sends the response on the returned channel.
func (r *Resolvers) QueryChan(ctx context.Context, msg *dns.Msg) chan *dns.Msg {
	ch := make(chan *dns.Msg, 2)
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
		return resp, nil
	}
}

func (r *Resolvers) enforceMaxQPS() {
	for {
		select {
		case <-r.done:
			return
		case <-r.queue.Signal():
			if r.maxSet {
				r.rate.Take()
			}
			e, ok := r.queue.Next()
			if !ok {
				continue
			}
			if req, ok := e.(*request); ok && req.Msg != nil {
				if res := r.randResolver(); res != nil {
					res.query(req)
					continue
				}
				req.errNoResponse()
			}
		}
	}
}

func (r *Resolvers) sendQueries() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		if !r.checkAllQueues() {
			time.Sleep(time.Millisecond)
		}
	}
}

func (r *Resolvers) checkAllQueues() bool {
	r.Lock()
	list := r.list
	r.Unlock()

	var sent bool
	cur := time.Now()
	for _, res := range list {
		select {
		case <-res.done:
			continue
		default:
		}
		if res.next.After(cur) {
			continue
		}
		select {
		case <-res.xchgQueue.Signal():
			res.writeNextMsg()
			sent = true
		default:
		}
	}
	return sent
}

func (r *Resolvers) initializeResolver(addr string, qps int) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}
	if res := r.searchList(addr); res != nil {
		return nil
	}

	var res *resolver
	c := dns.Client{UDPSize: dns.DefaultMsgSize}
	if conn, err := c.Dial(addr); err == nil {
		_ = conn.SetDeadline(time.Time{})
		res = &resolver{
			done:      make(chan struct{}, 2),
			xchgQueue: queue.NewQueue(),
			xchgs:     newXchgMgr(),
			address:   addr,
			qps:       qps,
			inc:       time.Second / time.Duration(qps),
			next:      time.Now(),
			conn:      conn,
		}
		go res.responses()
		go res.timeouts()
	}
	return res
}

func (r *Resolvers) stopResolver(idx int) {
	if idx >= r.Len() {
		return
	}

	r.Lock()
	res := r.list[idx]
	r.Unlock()

	select {
	case <-res.done:
		return
	default:
	}

	if !r.maxSet {
		r.qps -= res.qps
	}
	close(res.done)
	res.conn.Close()
	// Drains the xchgQueue of all requests and allows callers to return
	for {
		e, ok := res.xchgQueue.Next()
		if !ok {
			break
		}
		if req, ok := e.(*request); ok && req.Msg != nil {
			req.errNoResponse()
		}
	}
	// Drains the xchgs of all messages and allows callers to return
	for _, req := range res.xchgs.removeAll() {
		if req.Msg != nil {
			req.errNoResponse()
		}
	}
}

func (r *Resolvers) searchListWithLock(addr string) *resolver {
	r.Lock()
	defer r.Unlock()

	return r.searchList(addr)
}

func (r *Resolvers) searchList(addr string) *resolver {
	if ridx, found := r.rmap[addr]; found {
		return r.list[ridx]
	}
	return nil
}

// Random selection plus short scan for the resolver with shortest queue.
func (r *Resolvers) randResolver() *resolver {
	var low int
	var chosen *resolver

	for _, res := range r.randList() {
		select {
		case <-res.done:
			continue
		default:
		}
		if cur := res.xchgQueue.Len(); chosen == nil || cur < low {
			chosen = res
			low = cur
		}
		if low == 0 {
			break
		}
	}
	return chosen
}

func (r *Resolvers) randList() []*resolver {
	r.Lock()
	defer r.Unlock()

	var list []*resolver
	if rlen := len(r.list); rlen > 0 {
		for i, j := 0, rand.Intn(rlen); i < r.scan; i, j = i+1, (j+1)%rlen {
			list = append(list, r.list[j])
		}
	}
	return list
}

func min(x, y int) int {
	m := x
	if y < m {
		m = y
	}
	return m
}

func (r *resolver) query(req *request) {
	if err := r.xchgs.add(req); err != nil {
		req.errNoResponse()
		return
	}
	r.xchgQueue.Append(req)
}

func (r *resolver) writeNextMsg() {
	select {
	case <-r.done:
		return
	default:
	}

	element, ok := r.xchgQueue.Next()
	if !ok {
		return
	}

	req := element.(*request)
	select {
	case <-req.Ctx.Done():
		req.errNoResponse()
		return
	default:
	}
	if err := r.conn.WriteMsg(req.Msg); err != nil {
		_ = r.xchgs.remove(req.ID, req.Name)
		req.errNoResponse()
		return
	}
	// Set the timestamp for message expiration
	r.xchgs.updateTimestamp(req.ID, req.Name)
	// Update the time for the next query to be sent
	r.next = time.Now().Add(r.inc)
}

func (r *resolver) responses() {
	defer r.conn.Close()

	for {
		select {
		case <-r.done:
			return
		default:
		}
		if m, err := r.conn.ReadMsg(); err == nil && m != nil && len(m.Question) > 0 {
			if req := r.xchgs.remove(m.Id, m.Question[0].Name); req != nil {
				if m.Truncated {
					go r.tcpExchange(req)
					continue
				}
				req.Result <- m
			}
		}
	}
}

func (r *resolver) tcpExchange(req *request) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: time.Minute,
	}
	if m, _, err := client.Exchange(req.Msg, r.address); err == nil {
		req.Result <- m
		return
	}
	req.errNoResponse()
}

func (r *resolver) timeouts() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			for _, req := range r.xchgs.removeExpired() {
				if req.Msg != nil {
					req.errNoResponse()
				}
			}
		}
	}
}
