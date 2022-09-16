# Diet256
Diet256 is a centrally coordinated, densely connected overlay network, implementing the [INET256](https://github.com/inet256/inet256) [spec](https://github.com/inet256/inet256/blob/master/doc/10_Spec.md).
It's the same simple INET256 API, but without any of peering or routing configuration to manage.

Diet256 makes all its connections over The Internet using QUIC and uses a central server to discover the IP address of peers.
The central server is outside an INET256 application's security perimeter, and the worst thing it can do is misinform a client about the location of a peer.
It can't trick applications into sending or receiving messages to or from the wrong peers.

## Getting Started
Either download a binary from the release page or build from source.

### Installing From Source
In the repo, run `make install` and it will install to `$GOPATH/bin`.

## Run the Daemon
You can run diet256 as a fully functional INET256 implementation (instead of the reference implementation).

```shell
$ diet256 daemon
```

All the INET256 tools will work with diet256 including the IPv6 Portal.

## Using this Library
You can import this package as a go library and build an INET256 application without running any additional daemon processes.

```go
package main

import (
	"context"
	"crypto/ed25519"
	"log"

	"github.com/inet256/diet256"
	"github.com/inet256/inet256/pkg/inet256"
)

func main() {
	srv, err := diet256.New() // That's it; now you're ready to create Nodes.
	if err != nil {
		log.Fatal(err)
	}

	// Provide a key, which will determine the Node's local address
	_, privateKey, _ = ed25519.GenerateKey(nil)
	node, err := srv.Open(ctx, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	defer node.Close()
	log.Println("local node:", node.LocalAddr())

	// dst is the address of the peer you want to send to.
	dst := inet256.ID{}
	node.Send(context.Background(), dst, []byte("ping"))
}
```

## Run the IPv6 Portal In-Process
Normally, the IPv6 Portal runs as its own process, separate from the INET256 daemon.
You can do that with `inet256 ip6-portal`, if `diet256 daemon` or another INET256 implementation is running.

diet256 also supports an in process IPv6 portal.  You can launch that with
```shell
$ diet256 ip6-portal --private-key ./path/to/private_key.pem

INFO[0000] opened node jAeAUgztUHiKUgNpIDtzBcVm19Y9Y829MvhqFvG3VSY
INFO[0000] Created TUN utun2
INFO[0000] Local INET256: jAeAUgztUHiKUgNpIDtzBcVm19Y9Y829MvhqFvG3VSY
INFO[0000] Local IPv6: 200:603c:290:676a:83c4:5290:1b49:1db
```
And then you will have a TUN device connected to the diet256 network using the standard IPv6-to-INET256 address mapping.

## More
For more INET256 docs head over to [INET256](https://github.com/inet256/inet256).
