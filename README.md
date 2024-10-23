# UMAC in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/fakeboboliu/umac.svg)](https://pkg.go.dev/github.com/fakeboboliu/umac)

This is a Go implementation of the UMAC message authentication code used in OpenSSH.

As described in the [OpenSSH UMAC draft](https://www.openssh.com/txt/draft-miller-secsh-umac-01.txt) and [RFC4418](https://datatracker.ietf.org/doc/html/rfc4418),
UMAC is a (kinda) fast message authentication code, that is widely used in OpenSSH clients and servers.


## Benchmark

test on AWS EC2 t3.nano with full credits (actually a lightsail instance, but they are basically the same)

```
goos: linux
goarch: amd64
pkg: github.com/fakeboboliu/umac
cpu: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
BenchmarkHMACSHA256_1K
BenchmarkHMACSHA256_1K-2   	 1428729	      3614 ns/op	 283.34 MB/s
BenchmarkHMACSHA256_32
BenchmarkHMACSHA256_32-2   	10101997	       670.2 ns/op	  47.75 MB/s
BenchmarkHMACMD5_1K
BenchmarkHMACMD5_1K-2      	 2584860	      2161 ns/op	 473.94 MB/s
BenchmarkHMACMD5_32
BenchmarkHMACMD5_32-2      	14015890	       415.3 ns/op	  77.05 MB/s
BenchmarkUMAC64_1K
BenchmarkUMAC64_1K-2      	14754679	       379.2 ns/op	2700.67 MB/s
BenchmarkUMAC64_32
BenchmarkUMAC64_32-2       	42769585	       152.1 ns/op	 210.40 MB/s
BenchmarkUMAC128_1K
BenchmarkUMAC128_1K-2      	10143998	       595.2 ns/op	1720.37 MB/s
BenchmarkUMAC128_32
BenchmarkUMAC128_32-2      	36241742	       172.0 ns/op	 186.00 MB/s
```

The vCPU has no SHA extensions, so the performance of HMAC-SHA256 is not as good as other modern platforms.

For a CPU with SHA extensions, the performance of HMAC-SHA256 will be better than HMAC-MD5, while still way worse than UMAC.

HMAC-SHA1 will be nearly the same as HMAC-SHA256, so I didn't test it.

## Usage

Unlike HMAC, UMAC has a nonce needed per message, which is a 64-bit integer.

To fit `hash.Hash` interface, I placed the nonce set at `Sum([]byte)`,
you should pass a buffer that contains nonce, and it will be reused to store the result.

```go
package main

import (
    "fmt"
	
    "github.com/fakeboboliu/umac"
)

func main() {
    key := make([]byte, 16)
    mac := umac.New8(key)
    mac.Write([]byte("hello"))
	
    buf := make([]byte, 8)
    // -- set the nonce here --
	
    result := mac.Sum(buf)
    fmt.Printf("%x\n", result)
}
```

## How to use in ssh

A patch of golang.org/x/crypto/ssh is needed, I'll provide a patch version later.

## Why

I found only those secure MACs are included in golang.org/x/crypto/ssh, which obviously takes users' right to be insecure away.

I wrote this package to provide a way to users enjoy the freedom of taking their own fate becoming less secure.

There also be some ***TINY*** benchmark benefits, but freedom is the main reason.

Several naive optimizations are applied, but not as good as the original UMAC implementation.

## Thanks

- Ted Krovetz and [his website](https://fastcrypto.org/umac/)