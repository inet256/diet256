package diet256

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/inet256/diet256/internal/protocol"
	"github.com/inet256/inet256/pkg/inet256"
	"github.com/inet256/inet256/pkg/netutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type Node struct {
	client     *Client
	log        *logrus.Logger
	privateKey inet256.PrivateKey
	localAddr  inet256.ID
	tlsConfig  *tls.Config
	quicConfig *quic.Config

	baseConn net.PacketConn
	lis      quic.Listener
	tellHub  *netutil.TellHub

	ctrlClientMu sync.Mutex
	ctrlConn     quic.Connection
	ctrlClient   protocol.ControlClient

	mu       sync.RWMutex
	sessions map[sessionKey]quic.Connection

	ctx context.Context
	cf  context.CancelFunc
	eg  errgroup.Group
}

func newNode(c *Client, log *logrus.Logger, privateKey inet256.PrivateKey) (*Node, error) {
	baseConn, err := c.lpc(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	lis, err := quic.Listen(baseConn, generateServerTLS(privateKey), generateQUICConfig())
	if err != nil {
		return nil, err
	}
	ctx, cf := context.WithCancel(context.Background())
	n := &Node{
		client:     c,
		log:        log,
		privateKey: privateKey,
		localAddr:  inet256.NewAddr(privateKey.Public()),
		tlsConfig:  generateClientTLS(privateKey),
		quicConfig: generateQUICConfig(),

		baseConn: baseConn,
		lis:      lis,
		tellHub:  netutil.NewTellHub(),

		sessions: make(map[sessionKey]quic.Connection),
		ctx:      ctx,
		cf:       cf,
	}
	n.eg.Go(func() error {
		return n.baseReadLoop(ctx)
	})
	n.eg.Go(func() error {
		return n.listenLoop(ctx)
	})
	return n, nil
}

func (n *Node) Send(ctx context.Context, dst inet256.Addr, data []byte) error {
	sess, err := n.getSession(ctx, dst)
	if err != nil {
		return err
	}
	return sess.SendMessage(data)
}

func (n *Node) Receive(ctx context.Context, fn func(inet256.Message)) error {
	return n.tellHub.Receive(ctx, func(x p2p.Message[inet256.Addr]) {
		fn(inet256.Message{
			Src:     x.Src,
			Dst:     x.Dst,
			Payload: x.Payload,
		})
	})
}

func (n *Node) FindAddr(ctx context.Context, prefix []byte, nbits int) (inet256.Addr, error) {
	return retryN(5, 100*time.Millisecond, func() (inet256.Addr, error) {
		client, err := n.getControlClient(ctx)
		if err != nil {
			return inet256.Addr{}, err
		}
		res, err := client.FindAddr(ctx, &protocol.FindAddrReq{
			Prefix: prefix,
			Nbits:  int32(nbits),
		})
		if err != nil {
			return inet256.Addr{}, err
		}
		return inet256.AddrFromBytes(res.Addr), nil
	}, func(err error) {
		n.log.Warnf("error during FindAddr %v, retrying...", err)
	})
}

func (n *Node) LookupPublicKey(ctx context.Context, target inet256.Addr) (inet256.PublicKey, error) {
	return retryN[inet256.PublicKey](5, 100*time.Millisecond, func() (inet256.PublicKey, error) {
		client, err := n.getControlClient(ctx)
		if err != nil {
			return nil, err
		}
		res, err := client.LookupPublicKey(ctx, &protocol.LookupPublicKeyReq{
			Target: target[:],
		})
		if err != nil {
			return nil, err
		}
		return inet256.ParsePublicKey(res.PublicKey)
	}, func(err error) {
		n.log.Warnf("error during LookupPublicKey %v, retrying...", err)
	})
}

func (n *Node) LocalAddr() inet256.Addr {
	return n.localAddr
}

func (n *Node) PublicKey() inet256.PublicKey {
	return n.privateKey.Public()
}

func (n *Node) Close() error {
	n.cf()
	n.lis.Close()
	return n.eg.Wait()
}

func (n *Node) MTU(ctx context.Context, dst inet256.Addr) int {
	return inet256.MaxMTU
}

func (n *Node) getSession(ctx context.Context, dst inet256.Addr) (quic.Connection, error) {
	n.mu.RLock()
	sess1 := n.sessions[sessionKey{ID: dst, IsOutbound: false}]
	sess2 := n.sessions[sessionKey{ID: dst, IsOutbound: true}]
	n.mu.RUnlock()
	var sess quic.Connection
	switch {
	case sess1 != nil:
		sess = sess1
	case sess2 != nil:
		sess = sess2
	default:
		newSess, err := n.dialPeer(ctx, dst)
		if err != nil {
			return nil, err
		}
		sess = newSess
		go n.serveSession(sess, true)
	}
	return sess, nil
}

// dialPeer looks up the address of peer using the control plane and then attempts to connect to it.
func (n *Node) dialPeer(ctx context.Context, dst inet256.Addr) (ret quic.Connection, retErr error) {
	log := n.log.WithFields(logrus.Fields{"peer": dst})
	log.Infof("begin dial loop")
	defer func() {
		if retErr == nil {
			log.Infof("connected to peer at %v", ret.RemoteAddr())
		}
	}()
	return retryN(10, 100*time.Millisecond, func() (quic.Connection, error) {
		client, err := n.getControlClient(ctx)
		if err != nil {
			return nil, err
		}
		res, err := client.Dial(ctx, &protocol.DialReq{Target: dst[:]})
		if err != nil {
			return nil, err
		}
		raddr, err := netip.ParseAddrPort(res.Addr)
		if err != nil {
			return nil, err
		}
		raddr = fixAddrPort(raddr)
		return n.dialPeerAt(ctx, dst, raddr)
	}, func(err error) {
		n.log.Warnf("error dialing: %v, retying...", err)
	})
}

// dialPeerAddr connects to a specific peer at a specific netip.AddrPort
func (n *Node) dialPeerAt(ctx context.Context, id inet256.Addr, raddr netip.AddrPort) (quic.Connection, error) {
	log := n.log.WithFields(logrus.Fields{"peer": id, "raddr": raddr, "laddr": n.baseConn.LocalAddr()})
	udpAddr := net.UDPAddrFromAddrPort(raddr)
	// TODO: lock the remote address
	log.Infof("dialing peer")
	sess, err := quic.DialContext(ctx, n.baseConn, udpAddr, "", n.tlsConfig.Clone(), n.quicConfig)
	if err != nil {
		return nil, err
	}
	actualID, _, err := peerFromQUICConn(sess)
	if err != nil {
		return nil, err
	}
	if actualID != id {
		return nil, fmt.Errorf("got bad peer ID HAVE: %v WANT: %v", actualID, id)
	}
	return sess, nil
}

func (n *Node) listenLoop(ctx context.Context) error {
	return retryForever(ctx, time.Second, func() error {
		client, err := n.getControlClient(ctx)
		if err != nil {
			return err
		}
		lc, err := client.Listen(ctx, &protocol.ListenReq{})
		if err != nil {
			return err
		}
		for {
			lr, err := lc.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			id := inet256.AddrFromBytes(lr.Id)
			addrPort, err := netip.ParseAddrPort(lr.Addr)
			if err != nil {
				return err
			}
			addrPort = fixAddrPort(addrPort)
			go func() {
				sess, err := retryN(1, 100*time.Millisecond, func() (quic.Connection, error) {
					return n.dialPeerAt(n.ctx, id, addrPort)
				}, func(error) {})
				if err != nil {
					n.log.Warn("error during pre-emptive dial", err)
				} else {
					n.serveSession(sess, true)
				}
			}()
		}
	}, func(err error) {
		n.log.Warn("error in listen loop: ", err)
	})
}

func (node *Node) getControlClient(ctx context.Context) (protocol.ControlClient, error) {
	node.ctrlClientMu.Lock()
	defer node.ctrlClientMu.Unlock()
	if node.ctrlClient != nil {
		return node.ctrlClient, nil
	}
	cc, err := node.dialControlClient(ctx)
	if err != nil {
		return nil, err
	}
	node.ctrlClient = cc
	return cc, nil
}

func (node *Node) dialControlClient(ctx context.Context) (protocol.ControlClient, error) {
	tlsConfig := generateClientTLS(node.privateKey)
	gc, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(ctx context.Context, raddr string) (net.Conn, error) {
		serverAddr, err := node.client.getServerUDPAddr()
		if err != nil {
			return nil, err
		}
		var ctrlConn quic.Connection
		if node.ctrlConn != nil && node.ctrlConn.Context().Err() != nil {
			node.ctrlConn.CloseWithError(0, "connection errored")
			node.ctrlConn = nil
		}
		if node.ctrlConn == nil {
			node.log.Infof("dialing control plane %v...", serverAddr)
			sess, err := quic.Dial(node.baseConn, serverAddr, "", tlsConfig, generateQUICConfig())
			if err != nil {
				return nil, err
			}
			ctrlConn = sess
		}
		stream, err := ctrlConn.OpenStream()
		if err != nil {
			return nil, err
		}
		return newConn(ctrlConn, stream), nil
	}), grpc.WithTransportCredentials(transportCreds{ServerID: node.client.getServerID()}))
	if err != nil {
		return nil, err
	}
	return protocol.NewControlClient(gc), nil
}

func (node *Node) baseReadLoop(ctx context.Context) error {
	for {
		sess, err := node.lis.Accept(ctx)
		if err != nil {
			return err
		}
		serverAddr, err := node.client.getServerUDPAddr()
		if err != nil {
			return err
		}
		if sess.RemoteAddr().String() == serverAddr.String() {
			sess.CloseWithError(quic.ApplicationErrorCode(1), "server should not dial client")
			continue
		}
		go node.serveSession(sess, false)
	}
}

func (node *Node) serveSession(sess quic.Connection, isOutbound bool) error {
	ctx := node.ctx
	defer sess.CloseWithError(1, "closing session")
	from, _, err := peerFromQUICConn(sess)
	if err != nil {
		return err
	}
	sk := sessionKey{ID: from, IsOutbound: isOutbound}
	node.mu.Lock()
	if old, exists := node.sessions[sk]; exists {
		old.CloseWithError(1, "newer session")
		delete(node.sessions, sk)
	}
	node.sessions[sk] = sess
	node.mu.Unlock()
	defer func() {
		node.mu.Lock()
		delete(node.sessions, sk)
		node.mu.Unlock()
	}()
	for {
		data, err := sess.ReceiveMessage()
		if err != nil {
			return err
		}
		if err := func() error {
			return node.tellHub.Deliver(ctx, p2p.Message[inet256.Addr]{
				Src:     from,
				Dst:     node.localAddr,
				Payload: data,
			})
		}(); err != nil {
			node.log.Warn("error handling stream", err)
		}
	}
}

type sessionKey struct {
	ID         inet256.ID
	IsOutbound bool
}

func retryN[T any](n int, d time.Duration, fn func() (T, error), onError func(err error)) (T, error) {
	var retErr error
	for i := 0; i < n; i++ {
		y, err := fn()
		if err != nil {
			onError(err)
			retErr = err
		} else {
			return y, nil
		}
		time.Sleep(d)
	}
	var y T
	return y, retErr
}

func retryForever(ctx context.Context, d time.Duration, fn func() error, onErr func(error)) error {
	for {
		if err := fn(); err != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
}

func fixAddrPort(x netip.AddrPort) netip.AddrPort {
	ip := x.Addr()
	if ip.Is4In6() {
		return netip.AddrPortFrom(netip.AddrFrom4(ip.As4()), x.Port())
	}
	return x
}
