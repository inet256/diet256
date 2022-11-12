package diet256

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/inet256/diet256/internal/protocol"
	"github.com/inet256/inet256/pkg/inet256"
	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type serverConfig struct {
	FindAddrMinBits int32
}

type ServerOption func(c *serverConfig)

func WithFindAddrMinBits(n int) ServerOption {
	return func(c *serverConfig) {
		c.FindAddrMinBits = int32(n)
	}
}

type Server struct {
	privateKey inet256.PrivateKey
	config     serverConfig
	log        *logrus.Logger
	pconn      net.PacketConn
	lis        quic.Listener
	gs         *grpc.Server

	mu    sync.RWMutex
	peers map[inet256.Addr]*peerState

	cf context.CancelFunc
	eg errgroup.Group
	protocol.UnimplementedControlServer
}

func NewServer(pconn net.PacketConn, privateKey inet256.PrivateKey, opts ...ServerOption) (*Server, error) {
	config := serverConfig{
		FindAddrMinBits: 100,
	}
	for _, opt := range opts {
		opt(&config)
	}
	lis, err := quic.Listen(pconn, generateServerTLS(privateKey), &quic.Config{})
	if err != nil {
		return nil, err
	}
	gs := grpc.NewServer(grpc.Creds(transportCreds{}))
	ctx, cf := context.WithCancel(context.Background())
	s := &Server{
		privateKey: privateKey,
		config:     config,
		log:        logrus.StandardLogger(),
		pconn:      pconn,
		lis:        lis,
		gs:         gs,

		peers: make(map[inet256.Addr]*peerState),
		cf:    cf,
	}
	protocol.RegisterControlServer(gs, s)
	s.eg.Go(func() error {
		l := newListener(ctx, s.lis)
		return s.gs.Serve(l)
	})
	return s, nil
}

func (s *Server) Addr() string {
	return s.pconn.LocalAddr().String()
}

func (s *Server) PublicKey() inet256.PublicKey {
	return s.privateKey.Public()
}

func (s *Server) Close() error {
	s.cf()
	s.gs.Stop()
	s.log.Infof("stopped gRPC")
	s.lis.Close()
	s.log.Infof("closed QUIC listener")
	s.pconn.Close()
	s.log.Infof("closed PacketConn")
	s.log.Infof("waiting for everything to exit")
	return s.eg.Wait()
}

func (s *Server) Wait() error {
	return s.eg.Wait()
}

// Dial implements ControlServer.Dial
func (s *Server) Dial(ctx context.Context, req *protocol.DialReq) (*protocol.DialRes, error) {
	id, _, raddr := peerFromContext(ctx)
	log := s.log.WithFields(logrus.Fields{"id": id, "addr": raddr})
	target := inet256.AddrFromBytes(req.Target)
	log.Infof("recevied dial target=%v", target)
	s.mu.RLock()
	ps, exists := s.peers[target]
	if exists {
		ps.C <- peerInfo{ID: id, Addr: raddr}
	}
	s.mu.RUnlock()
	if !exists {
		return nil, status.Errorf(codes.NotFound, "no address found for %v", target)
	}
	return &protocol.DialRes{Addr: ps.Addr.String()}, nil
}

// Dial implements ControlServer.Listen
func (s *Server) Listen(req *protocol.ListenReq, srv protocol.Control_ListenServer) (retErr error) {
	id, pubKey, raddr := peerFromContext(srv.Context())
	log := s.log.WithFields(logrus.Fields{"id": id, "addr": raddr})
	log.Infof("peer connected")
	defer log.Infof("peer disconnected: %v", retErr)
	ch := s.subscribe(id, pubKey, raddr)
	defer s.unsubscribe(id, ch)
	for {
		select {
		case <-srv.Context().Done():
			return srv.Context().Err()
		case peerInfo, open := <-ch:
			if !open {
				return errors.New("another call to listen ended this one")
			}
			if err := srv.Send(&protocol.ListenRes{
				Id:   peerInfo.ID[:],
				Addr: peerInfo.Addr.String(),
			}); err != nil {
				return err
			}
		}
	}
}

// FindAddr implements ControlServer.FindAddr
func (s *Server) FindAddr(ctx context.Context, req *protocol.FindAddrReq) (*protocol.FindAddrRes, error) {
	id, _, raddr := peerFromContext(ctx)
	if req.Nbits < s.config.FindAddrMinBits {
		return nil, status.Errorf(codes.InvalidArgument, "server does not allow searching for short prefixes")
	}
	log := s.log.WithFields(logrus.Fields{"id": id, "addr": raddr})
	log.Infof("FindAddr on %q", req.Prefix)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id := range s.peers {
		if inet256.HasPrefix(id[:], req.Prefix, int(req.Nbits)) {
			return &protocol.FindAddrRes{Addr: id[:]}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "no address found with prefix")
}

// LookupPublicKey implements ControlServer.LookupPublicKey
func (s *Server) LookupPublicKey(ctx context.Context, req *protocol.LookupPublicKeyReq) (*protocol.LookupPublicKeyRes, error) {
	id, _, raddr := peerFromContext(ctx)
	targetID := inet256.AddrFromBytes(req.Target)
	log := s.log.WithFields(logrus.Fields{"id": id, "addr": raddr, "target": targetID})
	log.Infof("LookupPublicKey")

	s.mu.RLock()
	ps, exists := s.peers[targetID]
	s.mu.RUnlock()
	if !exists {
		return nil, status.Errorf(codes.NotFound, "no public keys found for %v", id)
	}
	return &protocol.LookupPublicKeyRes{
		PublicKey: inet256.MarshalPublicKey(ps.PublicKey),
	}, nil
}

func (s *Server) subscribe(id inet256.Addr, pubKey inet256.PublicKey, addr netip.AddrPort) chan peerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps, exists := s.peers[id]; exists {
		close(ps.C)
		delete(s.peers, id)
	}
	ps := &peerState{PublicKey: pubKey, Addr: addr, C: make(chan peerInfo)}
	s.peers[id] = ps
	return ps.C
}

func (s *Server) unsubscribe(id inet256.Addr, ch chan peerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// if it's the same one that we created then delete it.
	if ps, exists := s.peers[id]; exists && ps.C == ch {
		close(ch)
		delete(s.peers, id)
	}
}

func (s *Server) Run(ctx context.Context) error {
	s.eg.Go(func() error {
		logrus.Printf("control plane listening on %v...", s.lis.Addr())
		return s.gs.Serve(newListener(ctx, s.lis))
	})
	return s.eg.Wait()
}

type peerState struct {
	PublicKey inet256.PublicKey
	Addr      netip.AddrPort
	C         chan peerInfo
}

type listener struct {
	ctx context.Context
	lis quic.Listener

	cf    context.CancelFunc
	conns chan conn
	eg    errgroup.Group
}

func newListener(ctx context.Context, lis quic.Listener) listener {
	ctx, cf := context.WithCancel(ctx)
	l := listener{
		ctx: ctx,
		lis: lis,

		cf:    cf,
		conns: make(chan conn),
	}
	l.eg.Go(func() error {
		for {
			sess, err := l.lis.Accept(l.ctx)
			if err != nil {
				return err
			}
			go func() error {
				for {
					stream, err := sess.AcceptStream(l.ctx)
					if err != nil {
						sess.CloseWithError(1, err.Error())
						logrus.Warn(err)
						return nil
					}
					select {
					case <-l.ctx.Done():
						return nil
					case l.conns <- newConn(sess, stream):
					}
				}
			}()
		}
	})
	return l
}

func (l listener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	case conn := <-l.conns:
		return conn, nil
	}
}

func (l listener) Addr() net.Addr {
	return l.lis.Addr()
}

func (l listener) Close() error {
	l.cf()
	l.lis.Close()
	return l.eg.Wait()
}

type conn struct {
	sess quic.Connection
	quic.Stream
}

func newConn(sess quic.Connection, stream quic.Stream) conn {
	return conn{sess, stream}
}

func (c conn) LocalAddr() net.Addr {
	return c.sess.LocalAddr()
}

func (c conn) RemoteAddr() net.Addr {
	return c.sess.RemoteAddr()
}

type peerInfo struct {
	ID   inet256.ID
	Addr netip.AddrPort
}

type transportCreds struct {
	ServerID inet256.ID
}

// ClientHandshake does the authentication handshake specified by the
// corresponding authentication protocol on rawConn for clients. It returns
// the authenticated connection and the corresponding auth information
// about the connection.  The auth information should embed CommonAuthInfo
// to return additional information about the credentials. Implementations
// must use the provided context to implement timely cancellation.  gRPC
// will try to reconnect if the error returned is a temporary error
// (io.EOF, context.DeadlineExceeded or err.Temporary() == true).  If the
// returned error is a wrapper error, implementations should make sure that
// the error implements Temporary() to have the correct retry behaviors.
// Additionally, ClientHandshakeInfo data will be available via the context
// passed to this call.
//
// If the returned net.Conn is closed, it MUST close the net.Conn provided.
func (tc transportCreds) ClientHandshake(ctx context.Context, _ string, x net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c := x.(conn)
	id, pubKey, err := peerFromQUICConn(c.sess)
	if err != nil {
		return nil, nil, err
	}
	if id != tc.ServerID {
		return nil, nil, errors.New("server id does not match")
	}
	ai := authInfo{ID: id, PublicKey: pubKey}
	return x, ai, nil
}

// ServerHandshake does the authentication handshake for servers. It returns
// the authenticated connection and the corresponding auth information about
// the connection. The auth information should embed CommonAuthInfo to return additional information
// about the credentials.
//
// If the returned net.Conn is closed, it MUST close the net.Conn provided.
func (tc transportCreds) ServerHandshake(x net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := x.(conn)
	id, pubKey, err := peerFromQUICConn(conn.sess)
	if err != nil {
		return nil, nil, err
	}
	ai := authInfo{
		ID:        id,
		PublicKey: pubKey,
	}
	return conn, ai, nil
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (tc transportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{}
}

// Clone makes a copy of this TransportCredentials.
func (tc transportCreds) Clone() credentials.TransportCredentials {
	return tc
}

// OverrideServerName overrides the server name used to verify the hostname on the returned certificates from the server.
// gRPC internals also use it to override the virtual hosting name if it is set.
// It must be called before dialing. Currently, this is only used by grpclb.
func (tc transportCreds) OverrideServerName(string) error {
	return nil
}

type authInfo struct {
	ID        inet256.Addr
	PublicKey inet256.PublicKey
}

func (authInfo) AuthType() string {
	return "INET256"
}

func peerFromQUICConn(x quic.Connection) (inet256.ID, inet256.PublicKey, error) {
	tlsState := x.ConnectionState().TLS
	if len(tlsState.PeerCertificates) < 1 {
		return inet256.ID{}, nil, errors.New("no certificates")
	}
	cert := tlsState.PeerCertificates[0]
	pubKey := cert.PublicKey
	id := inet256.NewAddr(pubKey)
	return id, pubKey, nil
}

func peerFromContext(ctx context.Context) (inet256.Addr, inet256.PublicKey, netip.AddrPort) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		panic("grpc peer.FromContext returned nil")
	}
	raddr := peer.Addr.(*net.UDPAddr)
	id := peer.AuthInfo.(authInfo).ID
	pubKey := peer.AuthInfo.(authInfo).PublicKey
	return id, pubKey, raddr.AddrPort()
}
