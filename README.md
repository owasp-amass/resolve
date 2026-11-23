![GitHub Test Status](https://github.com/owasp-amass/resolve/workflows/tests/badge.svg)
[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/owasp-amass/resolve?tab=overview)
[![License](https://img.shields.io/github/license/owasp-amass/resolve)](https://www.apache.org/licenses/LICENSE-2.0)
[![CodeFactor](https://www.codefactor.io/repository/github/owasp-amass/resolve/badge)](https://www.codefactor.io/repository/github/owasp-amass/resolve)
[![Maintainability](https://api.codeclimate.com/v1/badges/35fb58e657b0f94870b0/maintainability)](https://codeclimate.com/github/owasp-amass/resolve/maintainability)
[![codecov](https://codecov.io/gh/owasp-amass/resolve/branch/master/graph/badge.svg?token=HDCWO273A1)](https://codecov.io/gh/owasp-amass/resolve)

# Leverage Many Recursive DNS Servers

Designed to support DNS brute-forcing with minimal system resources:

- Easy to send a large number of queries concurrently
- Hundreds of DNS nameservers can easily be leveraged
- A minimal number of goroutines are employed by the package
- Provides features like DNS wildcard detection and NSEC traversal

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/owasp-amass/resolve)](https://golang.org/dl/)

```bash
go get -v -u github.com/owasp-amass/resolve@main
```

## Usage

```go
qps := 15
var nameservers = []string{
	"8.8.8.8",        // Google
	"1.1.1.1",        // Cloudflare
	"9.9.9.9",        // Quad9
	"208.67.222.222", // Cisco OpenDNS
	"84.200.69.80",   // DNS.WATCH
	"64.6.64.6",      // Neustar DNS
	"8.26.56.26",     // Comodo Secure DNS
	"205.171.3.65",   // Level3
	"134.195.4.2",    // OpenNIC
	"185.228.168.9",  // CleanBrowsing
	"76.76.19.19",    // Alternate DNS
	"37.235.1.177",   // FreeDNS
	"77.88.8.1",      // Yandex.DNS
	"94.140.14.140",  // AdGuard
	"38.132.106.139", // CyberGhost
	"74.82.42.42",    // Hurricane Electric
	"76.76.2.0",      // ControlD
}
r := resolve.NewResolvers()
_ = r.AddResolvers(qps, nameservers...)
defer r.Stop()

ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
defer cancel()

ch := make(chan *dns.Msg, 100)
go func() {
	for _, name := range names {
		r.Query(ctx, resolve.QueryMsg(name, 1), ch)
	}
}()

for {
	select {
	case <-ctx.Done():
		return
	case resp := <-ch:
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			ans := ExtractAnswers(resp)
			domain, err := publicsuffix.EffectiveTLDPlusOne(ans[0].Name)

			if err == nil && !r.WildcardDetected(ctx, resp, domain) {
				fmt.Printf("%s resolved to %s\n", ans[0].Name, ans[0].Data)
			}
		}
	}
}
```

### Sharing nameservers between pools

A `servers.Registry` holds one nameserver per address for any number of pools, so a cap on the
queries per second sent to each nameserver holds across all of them. The registry expires the
unanswered queries itself, and `selectors.NewSharedRoundRobin` selects its nameservers without
closing them when a pool is done. `conn.LocalAddr` binds a pool's UDP sockets to a local address,
so its queries leave through the network interface that has it.

```go
reg := servers.NewRegistry(250*time.Millisecond, 15) // at most 15 queries per second per nameserver
defer reg.Close()

var servs []types.Nameserver
for _, addr := range []string{"8.8.8.8", "1.1.1.1"} {
	ns, err := reg.Get(addr)
	if err != nil {
		return err
	}
	servs = append(servs, ns)
}

sel := selectors.NewSharedRoundRobin(servs...)
conns := conn.New(runtime.NumCPU(), sel, conn.LocalAddr(netip.MustParseAddr("192.0.2.10")))
if conns == nil {
	return errors.New("the local address is not on a network interface")
}
p := pool.New(0, sel, conns, nil)
defer conns.Close()
defer p.Stop()
```

## Licensing [![License](https://img.shields.io/github/license/owasp-amass/resolve)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE).
