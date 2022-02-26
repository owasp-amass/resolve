# Fast Use of DNS Resolvers

![GitHub Test Status](https://github.com/caffix/resolve/workflows/tests/badge.svg)
[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/caffix/resolve?tab=overview)
[![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report](https://goreportcard.com/badge/github.com/caffix/resolve)](https://goreportcard.com/report/github.com/caffix/resolve)
[![CodeFactor](https://www.codefactor.io/repository/github/caffix/resolve/badge)](https://www.codefactor.io/repository/github/caffix/resolve)
[![Codecov](https://codecov.io/gh/caffix/resolve/branch/master/graph/badge.svg)](https://codecov.io/gh/caffix/resolve)
[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)

Designed to support DNS brute-forcing with a minimal number of network connections.

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/caffix/resolve)](https://golang.org/dl/)

```bash
go get -v -u github.com/caffix/resolve@master
```

## Usage

```go
var defaultResolvers = []string{
	"8.8.8.8",        // Google
	"1.1.1.1",        // Cloudflare
	"9.9.9.9",        // Quad9
	"208.67.222.222", // Cisco OpenDNS
	"84.200.69.80",   // DNS.WATCH
	"64.6.64.6",      // Verisign
	"8.26.56.26",     // Comodo Secure DNS
	"64.6.64.6",      // Neustar DNS
	"195.46.39.39",   // SafeDNS
	"185.228.168.9",  // CleanBrowsing
	"76.76.19.19",    // Alternate DNS
	"77.88.8.1",      // Yandex.DNS
	"94.140.14.140",  // AdGuard
	"216.146.35.35",  // Dyn
	"192.71.245.208", // OpenNIC
	"38.132.106.139", // CyberGhost
	"109.69.8.51",    // puntCAT
	"74.82.42.42",    // Hurricane Electric
}
r := resolve.NewResolvers()
r.AddResolvers(10, defaultResolvers...)
defer r.Stop()

ctx := context.Background()
ch := r.QueryChan(ctx, resolve.QueryMsg("mail.google.com", 1))

resp := <-ch
if resp.Rcode != dns.RcodeSuccess {
    return errors.New("query failed")
}

if r.WildcardType(ctx, resp, "google.com") != resolve.WildcardTypeNone {
    return errors.New("wildcard detected")
}

if len(resp.Answer) == 0 {
    return errors.New("zero answers returned")
}

fmt.Println(resp.Answer[0].Data)
```

## Licensing [![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE).
