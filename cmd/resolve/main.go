// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultRetries int  = 50
	defaultTimeout int  = 500
	defaultQuiet   bool = false
	defaultHelp    bool = false
)

type params struct {
	Log      *log.Logger
	Pool     *pool.Pool
	Requests chan string
	Qtypes   []uint16
	Quiet    bool
	Input    *os.File
	Output   *os.File
	LogFile  *os.File
	QPS      int
	Retries  int
	Detector *wildcards.Detector
	Help     bool
}

func main() {
	p, buf, err := ObtainParams(os.Args[1:])
	if err != nil {
		msg := err.Error()
		if buf != nil {
			msg = buf.String()
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	if p.Help && buf != nil {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n%s\n", path.Base(os.Args[0]), "[options]", buf.String())
		return
	}
	defer p.Pool.Stop()
	// Begin reading DNS names from input
	p.Requests = make(chan string, 500)
	go InputDomainNames(p.Input, p.Requests)

	EventLoop(p)
}

func ObtainParams(args []string) (*params, *bytes.Buffer, error) {
	var timeout int
	var queryTypes, rlist CommaSep
	var rpath, ipath, lpath, opath, detector string

	buf := new(bytes.Buffer)
	flags := flag.NewFlagSet("resolve", flag.ContinueOnError)
	flags.SetOutput(buf)

	p := new(params)
	flags.BoolVar(&p.Quiet, "q", defaultQuiet, "Quiet mode")
	flags.BoolVar(&p.Help, "h", defaultHelp, "Print usage information")
	flags.IntVar(&p.QPS, "qps", 0, "Number of queries sent to each resolver per second")
	flags.IntVar(&p.Retries, "c", defaultRetries, "Times each DNS name is attempted before giving up")
	flags.IntVar(&timeout, "timeout", defaultTimeout, "Milliseconds to wait before a request times out")
	flags.Var(&queryTypes, "t", `DNS record types comma-separated (default "A")`)
	flags.Var(&rlist, "r", "DNS resolver IP addresses comma-separated")
	flags.StringVar(&rpath, "rf", "", "File containing a DNS resolver IP address on each line")
	flags.StringVar(&detector, "d", "", "Set a resolver to perform DNS wildcard detection")
	flags.StringVar(&ipath, "i", "", "Read DNS names from the specified input file (default stdin)")
	flags.StringVar(&opath, "o", "", "Write DNS responses to the specified output file (default stdout)")
	flags.StringVar(&lpath, "l", "", "Errors are written to the specified log file (default stderr)")
	if err := flags.Parse(args); err != nil {
		return nil, buf, fmt.Errorf("%v", err)
	}
	if p.Help {
		flags.PrintDefaults()
		return p, buf, nil
	}
	if err := p.SetupFiles(lpath, opath, ipath); err != nil {
		return nil, nil, fmt.Errorf("failed to open files: %v", err)
	}
	p.Qtypes = StringsToQtypes(queryTypes)
	if len(p.Qtypes) == 0 {
		p.Qtypes = []uint16{dns.TypeA}
	}
	if err := p.SetupResolverPool(rlist, rpath, p.QPS, timeout, detector); err != nil {
		return nil, nil, fmt.Errorf("failed to setup the resolver pool: %v", err)
	}
	return p, nil, nil
}

func (p *params) SetupFiles(lpath, opath, ipath string) error {
	// Assign the correct log file
	p.LogFile = os.Stderr
	if lpath != "" {
		f, err := os.OpenFile(lpath, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("failed to open the %s file %s: %v", "log", lpath, err)
		}
		p.LogFile = f
	}
	p.Log = log.New(p.LogFile, "", log.Lmicroseconds)
	// Assign the correct output file
	if !p.Quiet {
		p.Output = os.Stdout
	}
	if opath != "" {
		f, err := os.OpenFile(opath, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("failed to open the %s file %s: %v", "output", opath, err)
		}
		p.Output = f
	}
	// Assign the correct input file
	p.Input = os.Stdin
	if ipath != "" {
		f, err := os.Open(ipath)
		if err != nil {
			return fmt.Errorf("failed to open the %s file %s: %v", "input", ipath, err)
		}
		p.Input = f
	}
	return nil
}

func (p *params) SetupResolverPool(list []string, rpath string, qps, timeout int, detector string) error {
	// Set the DNS query timeout value using the provided interval
	if timeout == 0 {
		timeout = 500
	}
	delay := time.Duration(timeout) * time.Millisecond

	// Load DNS resolvers into the pool
	if rpath != "" {
		list = append(list, ResolverFileList(rpath)...)
	}

	var sel types.Selector
	if llen := len(list); llen == 0 {
		sel = selectors.NewAuthoritative(delay, servers.NewNameserver)
	} else if llen == 1 {
		sel = selectors.NewSingle(delay, servers.NewNameserver(list[0]))
	} else {
		sel = selectors.NewRandom(delay)
		for _, addrstr := range list {
			sel.Add(servers.NewNameserver(addrstr))
		}
	}

	conns := conn.New(runtime.NumCPU(), sel)
	p.Pool = pool.New(0, sel, conns, p.Log)
	// Attempt to set a resolver to perform DNS wildcard detection
	if detector != "" {
		if _, _, err := net.SplitHostPort(detector); err != nil && net.ParseIP(detector) == nil {
			return fmt.Errorf("failed to provide a valid IP address for DNS wildcard detection: %s", detector)
		}

		serv := servers.NewNameserver(detector)
		dconns := conn.New(runtime.NumCPU(), selectors.NewSingle(delay, serv))
		p.Detector = wildcards.NewDetector(serv, dconns, p.Log)
	}
	return nil
}

func EventLoop(p *params) {
	var avg float32 = 1.0
	var count, persec, processing int
	finished := queue.NewQueue()
	responses := make(chan *dns.Msg, 500)
	queries := make(map[string]int, 500)
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case name := <-p.Requests:
			count += len(p.Qtypes)
			sendInitialRequests(context.Background(), name, queries, responses, p)
		case resp := <-responses:
			name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))
			k := key(name, resp.Question[0].Qtype)
			// Check if there was an error or timeout requiring another attempt
			if resp.Rcode == types.RcodeNoResponse {
				queries[k]++
				if queries[k] <= p.Retries {
					p.Pool.Query(context.Background(), utils.QueryMsg(name, resp.Question[0].Qtype), responses)
					continue
				}
			} else {
				persec++
				avg = update(avg, float32(queries[k]), float32(persec))
				if p.Output != nil {
					processing++
					go processResponse(context.Background(), name, resp, finished, p)
				}
			}
			count--
			delete(queries, k)
		case <-finished.Signal():
			if e, ok := finished.Next(); ok && e != nil {
				processing--
				if msg, ok := e.(*dns.Msg); ok && msg.Rcode != types.RcodeNoResponse {
					fmt.Fprintf(p.Output, "\n%s\n", e.(*dns.Msg))
				}
			}
		case <-t.C:
			if e, ok := finished.Next(); ok && e != nil {
				processing--
				if msg, ok := e.(*dns.Msg); ok && msg.Rcode != types.RcodeNoResponse {
					fmt.Fprintf(p.Output, "\n%s\n", e.(*dns.Msg))
				}
			}
		}
		// Have all the queries been handled?
		if count == 0 && processing == 0 && len(queries) == 0 {
			p.Log.Printf("Resolved %d DNS names that averaged %.2f query attempts\n", persec, avg)
			return
		}
	}
}

func key(name string, qtype uint16) string {
	return name + strconv.Itoa(int(qtype))
}

func update(avg, item, n float32) float32 {
	if a := ((avg * (n - 1)) / n) + (item / n); a > 1.0 {
		return a
	}
	return 1.0
}

// New names generate a request for each query type.
func sendInitialRequests(ctx context.Context, name string, queries map[string]int, responses chan *dns.Msg, p *params) {
	for _, qtype := range p.Qtypes {
		queries[key(name, qtype)] = 1
		p.Pool.Query(ctx, utils.QueryMsg(name, qtype), responses)
	}
}

func processResponse(ctx context.Context, name string, resp *dns.Msg, out queue.Queue, p *params) {
	if p.Detector != nil {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)

		if err != nil || p.Detector.WildcardDetected(ctx, resp, domain) {
			resp.Rcode = types.RcodeNoResponse
		}
	}
	out.Append(resp)
}
