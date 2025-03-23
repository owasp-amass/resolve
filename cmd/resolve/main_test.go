// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestObtainParams(t *testing.T) {
	cases := []struct {
		label    string
		args     []string
		ok       bool
		expected *params
	}{
		{
			label: "No args",
			args:  []string{},
			ok:    true,
			expected: &params{
				Qtypes:  []uint16{dns.TypeA},
				Quiet:   defaultQuiet,
				Retries: defaultRetries,
				Help:    defaultHelp,
			},
		}, {
			label:    "Invalid argument",
			args:     []string{"-v"},
			ok:       false,
			expected: &params{},
		}, {
			label: "Help requested",
			args:  []string{"-h"},
			ok:    true,
			expected: &params{
				Quiet:   defaultQuiet,
				Retries: defaultRetries,
				Help:    true,
			},
		}, {
			label:    "Cannot open input file",
			args:     []string{"-i", "../../example/input.txt"},
			ok:       false,
			expected: &params{},
		}, {
			label: "Many valid arguments",
			args:  []string{"-t", "CNAME,A,AAAA,TXT", "-c", "5", "-qps", "10", "-q", "-d", "8.8.8.8"},
			ok:    true,
			expected: &params{
				Qtypes:  []uint16{dns.TypeCNAME, dns.TypeA, dns.TypeAAAA, dns.TypeTXT},
				Quiet:   true,
				QPS:     10,
				Retries: 5,
				Help:    defaultHelp,
			},
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			p, buf, err := ObtainParams(c.args)
			if err == nil != c.ok {
				msg := fmt.Sprintf("Failed to return the correct error value when expecting success to be %t: %v", c.ok, err)
				if buf != nil {
					msg = msg + "\n" + buf.String()
				}
				t.Error(msg)
			}
			if p != nil && p.Help && buf == nil {
				t.Error("Failed to return a valid buffer when help was requested")
			}
			if p != nil && c.ok && !compareParams(p, c.expected) {
				t.Errorf("Got: %v; Expected: %v", p, c.expected)
			}
		}
		t.Run(c.label, f)
	}
}

func compareParams(got, expected *params) bool {
	if got.QPS != expected.QPS || got.Retries != expected.Retries ||
		got.Help != expected.Help || got.Quiet != expected.Quiet {
		return false
	}
	for i, qtype := range expected.Qtypes {
		if got.Qtypes[i] != qtype {
			return false
		}
	}
	return true
}

func TestSetupFiles(t *testing.T) {
	logfile, err := os.CreateTemp("", "log")
	if err != nil {
		t.Fatalf("Failed to open the temporary log file: %v", err)
	}

	output, err := os.CreateTemp("", "output")
	if err != nil {
		t.Fatalf("Failed to open the temporary output file: %v", err)
	}

	input, err := os.CreateTemp("", "input")
	if err != nil {
		t.Fatalf("Failed to open the temporary input file: %v", err)
	}

	cases := []struct {
		label    string
		paths    []string
		quiet    bool
		expected []string
	}{
		{
			label:    "No paths",
			paths:    []string{"", "", ""},
			expected: []string{"/dev/stderr", "/dev/stdout", "/dev/stdin"},
		}, {
			label:    "No specified log file",
			paths:    []string{"", output.Name(), input.Name()},
			expected: []string{"/dev/stderr", output.Name(), input.Name()},
		}, {
			label:    "No specified output file",
			paths:    []string{logfile.Name(), "", input.Name()},
			expected: []string{logfile.Name(), "/dev/stdout", input.Name()},
		}, {
			label:    "No specified output file in quiet mode",
			paths:    []string{logfile.Name(), "", input.Name()},
			quiet:    true,
			expected: []string{logfile.Name(), "", input.Name()},
		}, {
			label:    "No specified input file",
			paths:    []string{logfile.Name(), output.Name(), ""},
			expected: []string{logfile.Name(), output.Name(), "/dev/stdin"},
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			p := &params{Quiet: c.quiet}

			if err := p.SetupFiles(c.paths[0], c.paths[1], c.paths[2]); err != nil {
				t.Errorf("Failed setup the files: %v", err)
			}
			if got := p.LogFile.Name(); got != c.expected[0] {
				t.Errorf("Got: %s; Expected: %s", got, c.expected[0])
			}
			if got := p.Input.Name(); got != c.expected[2] {
				t.Errorf("Got: %s; Expected: %s", got, c.expected[2])
			}
			if got := p.Output; got != nil && c.quiet && c.paths[1] == "" {
				t.Errorf("Failed to return the expected nil output file")
			}
			if got := p.Output; (got == nil && !c.quiet && c.paths[1] != "") || (got != nil && got.Name() != c.expected[1]) {
				t.Errorf("Failed while expecting: %s", c.expected[1])
			}
			if c.expected[0] != "/dev/stderr" {
				p.LogFile.Close()
			}
			if p.Output != nil && c.expected[1] != "/dev/stdout" {
				p.Output.Close()
			}
			if c.expected[2] != "/dev/stdin" {
				p.Input.Close()
			}
		}
		t.Run(c.label, f)
	}
	// Remove the files and test for errors
	for i, f := range []*os.File{logfile, output, input} {
		name := f.Name()
		os.Remove(name)

		p := new(params)
		if i == 2 && p.SetupFiles("", "", name) == nil {
			t.Errorf("Failed to detect the removal of %s", name)
		}
	}
}

func TestSetupResolverPool(t *testing.T) {
	cases := []struct {
		label    string
		qps      int
		timeout  int
		detector string
		ok       bool
	}{
		{
			label: "Zero QPS",
			ok:    true,
		}, {
			label:   "Non-zero timeout",
			qps:     1,
			timeout: 200,
			ok:      true,
		}, {
			label:    "Invalid detector resolver",
			qps:      1,
			detector: "Not an IP",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			p := &params{QPS: c.qps}

			if err := p.SetupResolverPool(nil, "", c.qps, c.timeout, c.detector); err == nil != c.ok {
				t.Errorf("Got: %t; Expected: %t", err == nil, c.ok)
			}
		}
		t.Run(c.label, f)
	}
}

/*
func TestEventLoop(t *testing.T) {
	dns.HandleFunc("caffix.net.", eventLoopHandler)
	defer dns.HandleRemove("caffix.net.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("Unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	output, _ := os.Open(os.DevNull)
	p := &params{
		Log:     log.New(io.Discard, "", 0),
		QPS:     100,
		Qtypes:  []uint16{dns.TypeA},
		Output:  output,
		Retries: 5,
	}

	if err := p.SetupResolverPool([]string{addrstr}, "", 10, 100, addrstr); err != nil {
		t.Fatalf("Failed to setup the resolver pool: %v", err)
	}
	defer p.Pool.Stop()

	p.Requests = make(chan string, p.QPS)
	reader := strings.NewReader("www.caffix.net\nmail.caffix.net\nftp.caffix.net\ndrop.caffix.net")
	go InputDomainNames(reader, p.Requests)
	EventLoop(p)
}

func eventLoopHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	var addr string
	switch req.Question[0].Name {
	case "www.caffix.net.":
		addr = "192.168.1.14"
	case "mail.caffix.net.":
		addr = "192.168.1.15"
	case "ftp.caffix.net.":
		addr = "192.168.1.16"
	}

	if addr != "" {
		m.Answer = make([]dns.RR, 1)
		m.Answer[0] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP(addr),
		}
		_ = w.WriteMsg(m)
	}
}

func RunLocalUDPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return RunLocalServer(pc, nil, opts...)
}

func RunLocalServer(pc net.PacketConn, l net.Listener, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	server := &dns.Server{
		PacketConn: pc,
		Listener:   l,

		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	for _, opt := range opts {
		opt(server)
	}

	var (
		addr   string
		closer io.Closer
	)
	if l != nil {
		addr = l.Addr().String()
		closer = l
	} else {
		addr = pc.LocalAddr().String()
		closer = pc
	}
	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// if the channel is discarded and can happen in TestShutdownUDP.
	fin := make(chan error, 1)

	go func() {
		fin <- server.ActivateAndServe()
		closer.Close()
	}()

	waitLock.Lock()
	return server, addr, fin, nil
}
*/
