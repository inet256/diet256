package diet256

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/stdctx"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/inet256/inet256/pkg/inet256"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// var defaultEndpoint = mustParseEndpoint("AAA@example.com")

type ClientOption = func(*Client)

func WithEndpoint(id inet256.ID, addr string) ClientOption {
	return func(c *Client) {
		c.endpoint = Endpoint{ID: id, Addr: addr}
	}
}

type ListenPacketConn = func(ctx context.Context, network, addr string) (net.PacketConn, error)

func WithListenPacketConn(fn ListenPacketConn) ClientOption {
	return func(c *Client) {
		c.lpc = fn
	}
}

type Client struct {
	bgCtx    context.Context
	endpoint Endpoint
	lpc      ListenPacketConn

	mu    sync.RWMutex
	nodes map[inet256.ID]*Node
}

// New creates a new inet256.Service
func New(opts ...ClientOption) inet256.Service {
	ctx := context.Background()
	l, _ := zap.NewProduction()
	ctx = logctx.NewContext(ctx, l)
	c := &Client{
		bgCtx:    ctx,
		endpoint: defaultEndpoint,
		lpc: func(_ context.Context, network, addr string) (net.PacketConn, error) {
			laddr, err := net.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			return net.ListenUDP(network, laddr)
		},

		nodes: make(map[inet256.ID]*Node),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) Open(ctx context.Context, privateKey inet256.PrivateKey, opts ...inet256.NodeOption) (inet256.Node, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := inet256.NewAddr(privateKey.Public())
	if _, exists := c.nodes[id]; exists {
		err := errors.New("node is already open")
		logctx.Warnln(ctx, err)
		return nil, err
	}
	node, err := newNode(stdctx.Child(c.bgCtx, id.String()[:8]), c, privateKey)
	if err != nil {
		return nil, err
	}
	logctx.Infof(ctx, "opened node %s", id)
	c.nodes[id] = node
	return node, nil
}

func (c *Client) Drop(ctx context.Context, privateKey inet256.PrivateKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := inet256.NewAddr(privateKey.Public())
	var closeErr error
	if node, exists := c.nodes[id]; exists {
		closeErr = node.close()
	}
	delete(c.nodes, id)
	return closeErr
}

func (c *Client) getServerID() inet256.ID {
	return c.endpoint.ID
}

func (c *Client) getServerUDPAddr() (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", c.endpoint.Addr)
}

func generateClientTLS(privKey inet256.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey.BuiltIn())
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		NextProtos:         []string{"diet256"},
	}
}

func generateServerTLS(privKey inet256.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey.BuiltIn())
	localID := inet256.NewAddr(privKey.Public())
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"diet256"},
		ClientAuth:         tls.RequireAnyClientCert,
		ServerName:         localID.String(),
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) < 0 {
				return errors.New("must provide >= 1 certificate")
			}
			return nil
		},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
	}
}

// Endpoint is a INET256 address plus UDP address or domain name.
type Endpoint struct {
	ID   inet256.ID
	Addr string
}

// ParseEndpoint parses an endpoint in
// <INET256>@<host>:<port> format.
func ParseEndpoint(x []byte) (*Endpoint, error) {
	parts := bytes.SplitN(x, []byte("@"), 2)
	if len(parts) != 2 {
		panic(x)
	}
	id, err := inet256.ParseAddrBase64([]byte(parts[0]))
	if err != nil {
		panic(err)
	}
	return &Endpoint{ID: id, Addr: string(parts[1])}, nil
}

func mustParseEndpoint(x string) Endpoint {
	e, err := ParseEndpoint([]byte(x))
	if err != nil {
		panic(err)
	}
	return *e
}
