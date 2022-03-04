# Extremely fast use of DNS nameservers

![GitHub Test Status](https://github.com/caffix/resolve/workflows/tests/badge.svg)
[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/caffix/resolve?tab=overview)
[![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report](https://goreportcard.com/badge/github.com/caffix/resolve)](https://goreportcard.com/report/github.com/caffix/resolve)
[![CodeFactor](https://www.codefactor.io/repository/github/caffix/resolve/badge)](https://www.codefactor.io/repository/github/caffix/resolve)
[![Maintainability](https://api.codeclimate.com/v1/badges/2013705e6ec3b785e8f6/maintainability)](https://codeclimate.com/github/caffix/resolve/maintainability)
[![Codecov](https://codecov.io/gh/caffix/resolve/branch/master/graph/badge.svg)](https://codecov.io/gh/caffix/resolve)

[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)
[![Chat](https://img.shields.io/discord/433729817918308352.svg?logo=discord&style=flat-square)](https://discord.gg/rtN8GMd)
[![LinkedIn](https://img.shields.io/badge/-jeff%20foley-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/caffix/)](https://www.linkedin.com/in/caffix/)
[![Buy Me A Coffee](https://img.shields.io/badge/buy%20me%20a%20coffee-%23FFDD00.svg?&style=flat&logo=buy%20me%20a%20coffee&logoColor=black)](https://www.buymeacoffee.com/caffix)
[![PayPal](https://img.shields.io/badge/paypal-%2300457C.svg?&style=flat&logo=paypal&logoColor=white)](https://www.paypal.me/caffix)
[![Venmo](https://img.shields.io/badge/venmo-%233D95CE.svg?&style=flat&logo=venmo&logoColor=white)](https://venmo.com/caffix)
[![Cash App](https://img.shields.io/badge/-cash_app-00C244?style=flat-square&logo=cashapp&logoColor=fff)](https://cash.app/$caffix)
[![GitHub Sponsors](https://img.shields.io/badge/github%20sponsors-%23EA4AAA.svg?&style=flat&logo=github%20sponsors&logoColor=white)](https://github.com/sponsors/caffix)

---

Designed to support DNS brute-forcing with minimal system resources:

- Easy to send a large number of queries concurrently
- Hundreds of DNS nameservers can easily be leveraged
- A minimal number of goroutines are employed by the package
- Provides features like DNS wildcard detection and NSEC traversal

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
r.AddResolvers(10, defaultResolvers...)
defer r.Stop()

ctx := context.Background()
ch := r.QueryChan(ctx, resolve.QueryMsg("mail.google.com", 1))

resp := <-ch
if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
    return errors.New("zero answers returned")
}
if r.WildcardDetected(ctx, resp, "google.com") {
    return errors.New("wildcard detected")
}

fmt.Println(ExtractAnswers(resp)[0].Data)
```

## Licensing [![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE).
