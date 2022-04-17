package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"

	"github.com/inet256/diet256"
	"github.com/inet256/inet256/pkg/inet256"
	"github.com/inet256/inet256/pkg/inet256grpc"
	"github.com/inet256/inet256/pkg/inet256ipv6"
	"github.com/inet256/inet256/pkg/serde"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func main() {
	if err := NewRootCmd().Execute(); err != nil {
		log.Fatal(err)
	}
}

func NewRootCmd() *cobra.Command {
	c := &cobra.Command{
		Use: "diet256",
	}
	newNode := func(ctx context.Context, pk inet256.PrivateKey) (inet256.Node, error) {
		client := diet256.New()
		return client.Open(ctx, pk)
	}
	c.AddCommand(NewDaemonCmd())
	c.AddCommand(NewServeCmd())
	c.AddCommand(inet256ipv6.NewIP6PortalCmd(newNode))
	return c
}

func NewServeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "server <addr> <private_key_path>",
		Short: "run the diet256 coordination server",
		Args:  cobra.MinimumNArgs(2),
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		laddr, privateKeyPath := args[0], args[1]
		privateKey, err := LoadPrivateKey(privateKeyPath)
		if err != nil {
			return err
		}
		udpAddr, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return err
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		s, err := diet256.NewServer(udpConn, privateKey)
		if err != nil {
			return err
		}
		return s.Wait()
	}
	return c
}

func NewDaemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "run the diet256 daemon",
	}
	apiAddr := c.Flags().String("--api-addr", "127.0.0.1:2560", "--api-addr 0.0.0.0:8000")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		client := diet256.New()
		log := logrus.StandardLogger()
		l, err := net.Listen("tcp", *apiAddr)
		if err != nil {
			return err
		}
		gs := grpc.NewServer()
		server := inet256grpc.NewServer(client)
		inet256grpc.RegisterINET256Server(gs, server)
		log.Infof("serving on %v ...", l.Addr())
		return gs.Serve(l)
	}
	return c
}

func LoadPrivateKey(path string) (inet256.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return serde.ParsePrivateKeyPEM(data)
}
