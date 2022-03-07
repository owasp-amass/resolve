// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

func main() {
	var qps, retries, timeout int
	var queryTypes, rlist CommaSep
	var rpath, ipath, opath, detector string
	var help, quiet, verbose, detection bool

	flags := flag.NewFlagSet("resolve", flag.ExitOnError)
	flags.BoolVar(&quiet, "q", false, "Quiet mode")
	flags.BoolVar(&verbose, "v", false, "Verbose mode")
	flags.BoolVar(&help, "h", false, "Print usage information")
	flags.IntVar(&qps, "qps", 500, "Number of DNS queries sent to each resolver per second")
	flags.IntVar(&retries, "c", 50, "Number of times each DNS name is attempted before giving up")
	flags.IntVar(&timeout, "timeout", 500, "Number of milliseconds to wait before a request times out")
	flags.Var(&queryTypes, "t", `DNS record types comma-separated (default "A")`)
	flags.Var(&rlist, "r", "DNS resolver IP addresses comma-separated")
	flags.StringVar(&rpath, "rf", "", "File containing a DNS resolver IP address on each line")
	flags.StringVar(&detector, "d", "", "Set a resolver to perform DNS wildcard detection")
	flags.StringVar(&ipath, "i", "", "Read DNS names from the specified input file (default stdin)")
	flags.StringVar(&opath, "o", "", "Write DNS responses to the specified output file (default stdout)")

	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if help {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n", path.Base(os.Args[0]), "[options]")
		flags.PrintDefaults()
		os.Exit(0)
	}

	input := os.Stdin
	// Open a provide input file or use stdin
	if ipath != "" {
		var err error
		input, err = os.Open(ipath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open the input file %s: %v\n", ipath, err)
			os.Exit(1)
		}
		defer input.Close()
	}

	var output *os.File
	// Open a provided output file or use stdout
	if opath != "" {
		var err error
		output, err = os.OpenFile(opath, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open the output file %s: %v\n", opath, err)
			os.Exit(1)
		}
		defer output.Close()
	} else if !quiet {
		output = os.Stdout
	}

	r := resolve.NewResolvers()
	defer r.Stop()

	var nameservers []string
	// Load DNS resolvers into the pool
	for _, res := range rlist {
		nameservers = append(nameservers, res)
	}
	if l := len(rlist); l == 0 || (l > 0 && rpath != "") {
		nameservers = append(nameservers, ResolverList(rpath)...)
	}
	if err := r.AddResolvers(qps, nameservers...); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add the resolvers at a QPS of %d: %v\n", qps, err)
		os.Exit(1)
	}
	// Set the DNS query timeout value using the provided interval
	if timeout > 0 {
		resolve.QueryTimeout = time.Duration(timeout) * time.Millisecond
	}
	// Attempt to set a resolver to perform DNS wildcard detection
	if detector != "" {
		if net.ParseIP(detector) == nil {
			fmt.Fprintf(os.Stderr, "Failed to provide a valid IP address for DNS wildcard detection: %s\n", detector)
			os.Exit(1)
		}
		r.SetDetectionResolver(qps, detector)
		detection = true
	}
	// Check if the default query type should be added
	if len(queryTypes) == 0 {
		queryTypes = []string{"A"}
	}

	var qtypes []uint16
	// Build the list of DNS qtypes
	for _, t := range queryTypes {
		if qtype := StringToQtype(t); qtype != dns.TypeNone {
			qtypes = append(qtypes, qtype)
		}
	}
	if len(qtypes) == 0 {
		fmt.Fprintf(os.Stderr, "Failed to provide a valid DNS Qtype: %s\n", queryTypes)
		os.Exit(1)
	}
	// Begin reading DNS names from input
	requests := make(chan string, r.QPS())
	go InputDomainNames(input, requests)

	var avg float32 = 1.0
	done := make(chan struct{})
	ctx := context.Background()
	var count, persec, wilds int
	finished := make(chan *dns.Msg, r.QPS())
	responses := make(chan *dns.Msg, r.QPS())
	queries := make(map[string]int, r.QPS())
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-t.C:
			if verbose {
				fmt.Fprintf(os.Stderr, "%d DNS names resolved averaging %.2f query attempts\n", persec, avg)
			}
			avg = 0
			persec = 0
		case name := <-requests:
			// New names generate a request for each query type
			for _, qtype := range qtypes {
				count++
				queries[key(name, qtype)] = 1
				r.Query(ctx, resolve.QueryMsg(name, qtype), responses)
			}
		case resp := <-responses:
			t := resp.Question[0].Qtype
			name := resolve.RemoveLastDot(strings.ToLower(resp.Question[0].Name))
			k := key(name, t)
			// Check if there was an error or timeout requiring another attempt
			if resp.Rcode == resolve.RcodeNoResponse {
				queries[k]++
				if queries[k] <= retries {
					r.Query(ctx, resolve.QueryMsg(name, t), responses)
					continue loop
				}
			} else {
				persec++
				n := float32(persec)
				nminus := float32(persec - 1)
				avg = ((avg * nminus) / n) + (float32(queries[k]) / n)
				if avg < 1.0 {
					avg = 1.0
				}
				// Can the response be sent to output right away?
				if detection {
					wilds++
					go processWildcardDetection(ctx, resp, r, finished)
				} else if output != nil {
					fmt.Fprintf(output, "\n%s\n", resp)
				}
			}
			count--
			delete(queries, k)
		case msg := <-finished:
			if msg != nil && output != nil {
				fmt.Fprintf(output, "\n%s\n", msg)
			}
			wilds--
		}
		// Have all the queries been handled?
		if count == 0 && wilds == 0 && len(queries) == 0 {
			close(done)
		}
	}
}

func key(name string, qtype uint16) string {
	return name + strconv.Itoa(int(qtype))
}

func processWildcardDetection(ctx context.Context, resp *dns.Msg, r *resolve.Resolvers, out chan *dns.Msg) {
	name := resolve.RemoveLastDot(strings.ToLower(resp.Question[0].Name))

	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err == nil && !r.WildcardDetected(ctx, resp, domain) {
		out <- resp
		return
	}
	out <- nil
}
