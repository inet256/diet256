package diet256

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/inet256/inet256/pkg/inet256"
	"github.com/inet256/inet256/pkg/inet256test"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	s := newTestServer(t, 0)
	client := newTestClient(t, s)
	ctx := context.Background()

	k1 := inet256test.NewPrivateKey(t, 101)
	node1, err := client.Open(ctx, k1)
	require.NoError(t, err)
	defer node1.Close()

	k2 := inet256test.NewPrivateKey(t, 102)
	node2, err := client.Open(ctx, k2)
	require.NoError(t, err)
	defer node2.Close()

	time.Sleep(100 * time.Millisecond)
	pubKey, err := node1.LookupPublicKey(ctx, inet256.NewAddr(k2.Public()))
	require.NoError(t, err)
	t.Log(pubKey)

	//inet256test.TestSendRecvOne(t, node1, node2)
}

func TestINET256Service(t *testing.T) {
	inet256test.TestService(t, func(t testing.TB, xs []inet256.Service) {
		srv := newTestServer(t, 0)
		for i := range xs {
			xs[i] = newTestClient(t, srv)
		}
	})
}

func newTestServer(t testing.TB, i int) *Server {
	serverAddr := "127.0.0.1:"
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	return newTestServerFromConn(t, i, udpConn)
}

func newTestServerFromConn(t testing.TB, i int, pc net.PacketConn) *Server {
	pk := inet256test.NewPrivateKey(t, i)
	s, err := NewServer(pc, pk, WithFindAddrMinBits(0))
	require.NoError(t, err)
	//t.Cleanup(func() { s.Close() })
	return s
}

func newTestClient(t testing.TB, s *Server, opts ...ClientOption) *Client {
	opts = append(opts, WithEndpoint(inet256.NewAddr(s.PublicKey()), s.Addr()))
	client := New(opts...)
	return client.(*Client)
}
