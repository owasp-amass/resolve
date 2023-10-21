// Copyright © by Jeff Foley 2022-2023. All rights reserved.
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
	"strconv"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultQPS     int  = 500
	defaultRetries int  = 50
	defaultTimeout int  = 500
	defaultQuiet   bool = false
	defaultHelp    bool = false
)

type params struct {
	Log       *log.Logger
	Pool      *resolve.Resolvers
	Requests  chan string
	Qtypes    []uint16
	Quiet     bool
	Input     *os.File
	Output    *os.File
	LogFile   *os.File
	QPS       int
	Retries   int
	Detection bool
	Help      bool
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
	p.Requests = make(chan string, p.QPS)
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
	flags.IntVar(&p.QPS, "qps", defaultQPS, "Number of queries sent to each resolver per second")
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
	if err := p.SetupResolverPool(rlist, rpath, timeout, detector); err != nil {
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

func (p *params) SetupResolverPool(list []string, rpath string, timeout int, detector string) error {
	p.Pool = resolve.NewResolvers()

	// Load DNS resolvers into the pool
	if l := len(list); l == 0 || rpath != "" {
		list = append(list, ResolverFileList(rpath)...)
	}
	if err := p.Pool.AddResolvers(p.QPS, list...); err != nil {
		p.Pool.Stop()
		return fmt.Errorf("failed to add the resolvers at a QPS of %d: %v", p.QPS, err)
	}
	// Set the DNS query timeout value using the provided interval
	if timeout > 0 {
		p.Pool.SetTimeout(time.Duration(timeout) * time.Millisecond)
	}
	// Attempt to set a resolver to perform DNS wildcard detection
	if detector != "" {
		if _, _, err := net.SplitHostPort(detector); err != nil && net.ParseIP(detector) == nil {
			p.Pool.Stop()
			return fmt.Errorf("failed to provide a valid IP address for DNS wildcard detection: %s", detector)
		}
		p.Pool.SetDetectionResolver(p.QPS, detector)
		p.Detection = true
	}
	return nil
}

func EventLoop(p *params) {
	var avg float32 = 1.0
	var count, persec, processing int
	finished := queue.NewQueue()
	responses := make(chan *dns.Msg, p.QPS*2)
	queries := make(map[string]int, p.QPS)
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			p.Log.Printf("Resolved %d DNS names that averaged %.2f query attempts\n", persec, avg)
			avg, persec = 1.0, 0
		case name := <-p.Requests:
			count += len(p.Qtypes)
			sendInitialRequests(context.Background(), name, queries, responses, p)
		case resp := <-responses:
			name := resolve.RemoveLastDot(strings.ToLower(resp.Question[0].Name))
			k := key(name, resp.Question[0].Qtype)
			// Check if there was an error or timeout requiring another attempt
			if resp.Rcode == resolve.RcodeNoResponse {
				queries[k]++
				if queries[k] <= p.Retries {
					p.Pool.Query(context.Background(), resolve.QueryMsg(name, resp.Question[0].Qtype), responses)
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
				fmt.Fprintf(p.Output, "\n%s\n", e.(*dns.Msg))
			}
			processing--
		}
		// Have all the queries been handled?
		if count == 0 && processing == 0 && len(queries) == 0 {
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
		p.Pool.Query(ctx, resolve.QueryMsg(name, qtype), responses)
	}
}

func processResponse(ctx context.Context, name string, resp *dns.Msg, out queue.Queue, p *params) {
	if p.Detection {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)

		if err != nil || p.Pool.WildcardDetected(ctx, resp, domain) {
			resp = nil
		}
	}
	out.Append(resp)
}
