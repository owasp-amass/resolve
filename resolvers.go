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
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
)

const maxScanLen int = 10

type Resolvers struct {
	done      chan struct{}
	log       *log.Logger
	list      []*resolver
	rmap      map[string]int
	wildChans *wildcardChans
}

type resolver struct {
	done      chan struct{}
	xchgQueue queue.Queue
	xchgs     *xchgManager
	address   string
	qps       int
	inc       time.Duration
	next      time.Time
	conn      *dns.Conn
}

// NewResolvers initializes a Resolvers that starts with the provided list of DNS resolver IP addresses.
func NewResolvers() *Resolvers {
	r := &Resolvers{
		done: make(chan struct{}, 2),
		log:  log.New(ioutil.Discard, "", 0),
		rmap: make(map[string]int),
		wildChans: &wildcardChans{
			WildcardReq:     queue.NewQueue(),
			IPsAcrossLevels: make(chan *ipsAcrossLevels, 10),
			TestResult:      make(chan *testResult, 10),
		},
	}

	go r.sendQueries()
	go r.manageWildcards()
	return r
}

func (r *Resolvers) AddLogger(l *log.Logger) {
	r.log = l
}

// AddResolvers initializes and adds new resolvers to the pool of resolvers.
func (r *Resolvers) AddResolvers(qps int, addrs ...string) {
	if qps == 0 {
		return
	}
	for _, addr := range addrs {
		if res := r.initializeResolver(addr, qps); res != nil {
			r.rmap[res.address] = len(r.list)
			r.list = append(r.list, res)
		}
	}
}

func (r *Resolvers) Stop() {
	select {
	case <-r.done:
		return
	default:
	}

	close(r.done)
	for i := 0; i < len(r.list); i++ {
		r.stopResolver(i)
	}
}

func (r *Resolvers) Query(ctx context.Context, msg *dns.Msg, ch chan *dns.Msg) {
	select {
	case <-ctx.Done():
	case <-r.done:
	default:
		if res := r.randResolver(); res != nil {
			res.query(&resolveRequest{
				Ctx:    ctx,
				ID:     msg.Id,
				Name:   RemoveLastDot(msg.Question[0].Name),
				Qtype:  msg.Question[0].Qtype,
				Msg:    msg,
				Result: ch,
			})
			return
		}
	}
	// Failed to perform the query
	ch <- msg
}

func (r *Resolvers) QueryChan(ctx context.Context, msg *dns.Msg) chan *dns.Msg {
	ch := make(chan *dns.Msg, 2)
	r.Query(ctx, msg, ch)
	return ch
}

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

func (r *Resolvers) sendQueries() {
	sent := true
loop:
	for {
		select {
		case <-r.done:
			break loop
		default:
		}

		if !sent {
			time.Sleep(time.Millisecond)
		}
		sent = false

		cur := time.Now()
		for _, res := range r.list {
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
	}
	// Drains the xchgQueue of all requests and allows callers to return
	for _, res := range r.list {
		select {
		case <-res.done:
			continue
		default:
		}
		for {
			e, ok := res.xchgQueue.Next()
			if !ok {
				break
			}
			if req, ok := e.(*resolveRequest); ok && req.Msg != nil {
				req.Result <- req.Msg
			}
		}
	}
}

func (r *Resolvers) initializeResolver(addr string, qps int) *resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Add the default port number to the IP address
		addr = net.JoinHostPort(addr, "53")
	}
	if qps <= 0 {
		return nil
	}

	c := dns.Client{UDPSize: dns.DefaultMsgSize}
	conn, err := c.Dial(addr)
	if err != nil {
		r.log.Printf("Failed to establish a UDP connection to %s : %v", addr, err)
		return nil
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		r.log.Printf("Failed to clear the read deadline for the UDP connection to %s : %v", addr, err)
		return nil
	}

	res := &resolver{
		done:      make(chan struct{}, 2),
		xchgQueue: queue.NewQueue(),
		xchgs:     newXchgManager(),
		address:   addr,
		qps:       qps,
		inc:       time.Second / time.Duration(qps),
		next:      time.Now(),
		conn:      conn,
	}

	go res.responses()
	go res.timeouts()
	return res
}

func (r *Resolvers) stopResolver(idx int) {
	if idx >= len(r.list) {
		return
	}

	res := r.list[idx]
	select {
	case <-res.done:
		return
	default:
	}
	close(res.done)
}

func (r *Resolvers) randResolver() *resolver {
	var low int
	var chosen *resolver
	rlen := len(r.list)
	scan := maxScanLen
	if scan > rlen {
		scan = rlen
	}
	// Random selection plus short scan for the resolver with shortest queue
	for i, j := 0, rand.Intn(rlen); i < maxScanLen; i, j = i+1, (j+1)%rlen {
		res := r.list[j]
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

func (r *resolver) query(req *resolveRequest) {
	if err := r.xchgs.add(req); err != nil {
		req.Result <- req.Msg
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

	req := element.(*resolveRequest)
	select {
	case <-req.Ctx.Done():
		req.Result <- req.Msg
		return
	default:
	}

	if err := r.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = r.xchgs.remove(req.ID, req.Name)
		req.Result <- req.Msg
		return
	}
	if err := r.conn.WriteMsg(req.Msg); err != nil {
		_ = r.xchgs.remove(req.ID, req.Name)
		req.Result <- req.Msg
		return
	}
	// Set the timestamp for message expiration
	r.xchgs.updateTimestamp(req.ID, req.Name)
	// Update the time for the next query to be sent
	r.next = time.Now().Add(r.inc)
}

func (r *resolver) timeouts() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-r.done:
			break loop
		case <-t.C:
			for _, req := range r.xchgs.removeExpired() {
				if req.Msg != nil {
					req.Result <- req.Msg
				}
			}
		}
	}
	// Drains the xchgs of all messages and allows callers to return
	for _, req := range r.xchgs.removeAll() {
		if req.Msg != nil {
			req.Result <- req.Msg
		}
	}
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

func (r *resolver) tcpExchange(req *resolveRequest) {
	client := dns.Client{
		Net:     "tcp",
		Timeout: time.Minute,
	}

	if m, _, err := client.Exchange(req.Msg, r.address); err == nil {
		req.Result <- m
		return
	}
	req.Result <- req.Msg
}
