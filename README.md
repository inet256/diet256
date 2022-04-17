# Diet256
Diet256 is a centrally coordinated, densley connected overlay network, implementing the INET256 spec.

## Getting Started
Either download a binary from the release page or build from source.

### Installing From Source
In the repo, run `make install` and it will install to `$GOPATH/bin`

## Run the Daemon
You can run diet256 as a fully functional INET256 implementation (instead of the reference implementation).

```bash
$ diet256 daemon
```

All the INET256 tools will work with diet256 including the IPv6 Portal.

## Using this Library
You can import this package as a go library and build an INET256 application without running any additional daemon processes.

```go
package main

import (
	"context"

	"github.com/inet256/diet256"
	"github.com/inet256/inet256/pkg/inet256"
)

func main() {
	srv, err := diet256.New() // That's it; now you're ready to communicate with other Nodes.
	if err != nil {
		log.Fatal(err)
	}

	// Provide a key, which will determine the Node's local address
	var privateKey inet256.PrivateKey
	n, err := srv.Open(ctx, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	defer n.Close()
	// dst is the address of the peer you want to send to.
	dst := inet256.ID{}
	n.Tell(context.Background(), dst, []byte("ping"))
}
```

## Run the IPv6 Portal In-Process
Normally, the IPv6 Portal runs as its own process, separate from the INET256 daemon.
You can do that with `inet256 ip6-portal`, if `diet256 daemon` or another INET256 implementation is running.

diet256 also supports an in process IPv6 portal.  You can launch that with
```
$ diet256 ip6-portal --private-key ./path/to/private_key.pem
```
And then you will have a TUN device connected to the diet256 network.

For more INET256 docs head over to [INET256](https://github.com/inet256/inet256).
