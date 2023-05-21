package diet256

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/inet256/inet256/pkg/inet256test"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
	"tailscale.com/tstest/natlab"
)

type NATLabSetup = func(t testing.TB) (s *Server, c1, c2 *Client)

func TestNATLab(t *testing.T) {
	ctx := context.Background()
	type testCase struct {
		Name  string
		Setup NATLabSetup
	}
	for _, tc := range []testCase{
		{
			Name: "NoNAT",
			Setup: func(t testing.TB) (s *Server, c1, c2 *Client) {
				internet := natlab.NewInternet()
				// server
				serverMach := natlab.Machine{Name: "server"}
				serverIf1 := serverMach.Attach("eth0", internet).V4().String()
				serverConn, err := serverMach.ListenPacket(ctx, "udp4", serverIf1+":0")
				require.NoError(t, err)
				s = newTestServerFromConn(t, 0, serverConn)

				// client 1
				c1Mach := &natlab.Machine{Name: "client1"}
				c1Iface := c1Mach.Attach("eth0", internet)
				c1 = newClientMachIf(t, s, c1Mach, c1Iface)

				// client 2
				c2Mach := &natlab.Machine{Name: "client2"}
				c2Iface := c2Mach.Attach("eth0", internet)
				c2 = newClientMachIf(t, s, c2Mach, c2Iface)
				return s, c1, c2
			},
		},
		{
			Name: "EndpointIndependentNAT",
			Setup: func(t testing.TB) (s *Server, c1, c2 *Client) {
				internet := natlab.NewInternet()

				serverMach := natlab.Machine{Name: "server"}
				serverIf1 := serverMach.Attach("eth0", internet).V4().String()
				serverConn, err := serverMach.ListenPacket(ctx, "udp4", serverIf1+":0")
				require.NoError(t, err)
				s = newTestServerFromConn(t, 0, serverConn)

				natType, fwType := natlab.EndpointIndependentNAT, natlab.EndpointIndependentFirewall
				c1 = setupNATClient(t, s, internet, natType, fwType, 1)
				c2 = setupNATClient(t, s, internet, natType, fwType, 2)
				return s, c1, c2
			},
		},
		{
			Name: "AddressDependentNAT",
			Setup: func(t testing.TB) (s *Server, c1, c2 *Client) {
				internet := natlab.NewInternet()

				serverMach := natlab.Machine{Name: "server"}
				serverIf1 := serverMach.Attach("eth0", internet).V4().String()
				serverConn, err := serverMach.ListenPacket(ctx, "udp4", serverIf1+":0")
				require.NoError(t, err)
				s = newTestServerFromConn(t, 0, serverConn)

				natType, fwType := natlab.AddressDependentNAT, natlab.AddressDependentFirewall
				c1 = setupNATClient(t, s, internet, natType, fwType, 1)
				c2 = setupNATClient(t, s, internet, natType, fwType, 2)
				return s, c1, c2
			},
		},
		{
			Name: "AddressAndPortDependentNATNoFirewall",
			Setup: func(t testing.TB) (s *Server, c1, c2 *Client) {
				internet := natlab.NewInternet()

				serverMach := natlab.Machine{Name: "server"}
				serverIf1 := serverMach.Attach("eth0", internet).V4().String()
				serverConn, err := serverMach.ListenPacket(ctx, "udp4", serverIf1+":0")
				require.NoError(t, err)
				s = newTestServerFromConn(t, 0, serverConn)

				natType, fwType := natlab.AddressAndPortDependentNAT, natlab.EndpointIndependentFirewall
				c1 = setupNATClient(t, s, internet, natType, fwType, 1)
				c2 = setupNATClient(t, s, internet, natType, fwType, 2)
				return s, c1, c2
			},
		},
		{
			Name: "AddressAndPortDependentNAT",
			Setup: func(t testing.TB) (s *Server, c1, c2 *Client) {
				t.Skip("We can't do AddressAndPortDependent NATs yet.  This does pass without the firewall")
				internet := natlab.NewInternet()

				serverMach := natlab.Machine{Name: "server"}
				serverIf1 := serverMach.Attach("eth0", internet).V4().String()
				serverConn, err := serverMach.ListenPacket(ctx, "udp4", serverIf1+":0")
				require.NoError(t, err)
				s = newTestServerFromConn(t, 0, serverConn)

				natType, fwType := natlab.AddressAndPortDependentNAT, natlab.AddressAndPortDependentFirewall
				c1 = setupNATClient(t, s, internet, natType, fwType, 1)
				c2 = setupNATClient(t, s, internet, natType, fwType, 2)
				return s, c1, c2
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			_, c1, c2 := tc.Setup(t)
			n1, err := c1.Open(ctx, inet256test.NewPrivateKey(t, 101))
			require.NoError(t, err)
			n2, err := c2.Open(ctx, inet256test.NewPrivateKey(t, 102))
			require.NoError(t, err)
			inet256test.TestSendRecvOne(t, n1, n2)
		})
	}
}

// newClientMachIf creates a client connected to the Server s, using mach, and iface for connections.
func newClientMachIf(t testing.TB, s *Server, mach *natlab.Machine, iface *natlab.Interface) *Client {
	c := newTestClient(t, s, WithListenPacketConn(func(ctx context.Context, network string, addr string) (net.PacketConn, error) {
		addr = iface.V4().String() + ":0"
		logctx.Infof(ctx, "client listening on %s", addr)
		return mach.ListenPacket(ctx, "udp", addr)
	}))
	return c
}

func setupNATClient(t testing.TB, s *Server, wanNet *natlab.Network, natType natlab.NATType, fwType natlab.FirewallType, i int) *Client {
	// lan
	lan := &natlab.Network{
		Name:    "lan" + strconv.Itoa(i),
		Prefix4: netaddr.MustParseIPPrefix("192.168.1.0/24"),
	}
	// router
	natMach := &natlab.Machine{
		Name: "nat" + strconv.Itoa(i),
	}
	natWAN := natMach.Attach("wan", wanNet)
	natLAN := natMach.Attach("lan", lan)
	lan.SetDefaultGateway(natLAN)
	natMach.PacketHandler = &natlab.SNAT44{
		Type:              natType,
		ExternalInterface: natWAN,
		Machine:           natMach,
		Firewall: &natlab.Firewall{
			Type:             fwType,
			TrustedInterface: natLAN,
		},
	}
	// client
	cMach := &natlab.Machine{
		Name: "client" + strconv.Itoa(i),
	}
	cIface := cMach.Attach("eth", lan)
	return newClientMachIf(t, s, cMach, cIface)
}
