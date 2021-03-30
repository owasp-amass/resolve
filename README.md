# Fast Use of DNS Resolvers

![GitHub Test Status](https://github.com/caffix/resolve/workflows/tests/badge.svg)
[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/caffix/resolve?tab=overview)
[![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report](https://goreportcard.com/badge/github.com/caffix/resolve)](https://goreportcard.com/report/github.com/caffix/resolve)
[![CodeFactor](https://www.codefactor.io/repository/github/caffix/pipeline/badge)](https://www.codefactor.io/repository/github/caffix/resolve)
[![Codecov](https://codecov.io/gh/caffix/resolve/branch/master/graph/badge.svg)](https://codecov.io/gh/caffix/resolve)
[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)

Designed to support DNS brute-forcing with a minimal number of network connections.

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/caffix/resolve)](https://golang.org/dl/)

```bash
go get -v -u github.com/caffix/resolve
```

## Usage

The `Resolver` type from this package represents a DNS resolver or group of resolvers that support two primary actions: DNS queries and wildcard detection. Requests made to the same Resolver are performed asynchronously at the rate provided to the constructor of queries per second. DNS queries returning responses indicating success can then be checked for wildcards using the built-in detection.

```go
r := resolve.NewBaseResolver("8.8.8.8", 10, nil)

msg := resolve.QueryMsg("mail.google.com", 1)
resp, err := r.Query(context.TODO(), msg, resolve.PriorityNormal, nil)
if err != nil {
    return
}

if r.WildcardType(context.TODO(), resp, "google.com") != resolve.WildcardTypeNone {
    return
}
```

## Licensing [![License](https://img.shields.io/github/license/caffix/resolve)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE).
