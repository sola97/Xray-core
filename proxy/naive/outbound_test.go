package naive

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
)

type fakeNativeClient struct {
	resetCount atomic.Int32
	closeCount atomic.Int32
}

type recordingNativeClient struct {
	fakeNativeClient
	destination M.Socksaddr
	peer        net.Conn
}

func (c *recordingNativeClient) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	client, peer := net.Pipe()
	c.destination = destination
	c.peer = peer
	return client, nil
}

func (*fakeNativeClient) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (*fakeNativeClient) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (*fakeNativeClient) DialEarly(context.Context, M.Socksaddr) (cronet.NaiveConn, error) {
	return nil, errors.New("not used")
}

func (c *fakeNativeClient) CloseAllConnections() {
	c.resetCount.Add(1)
}

func (c *fakeNativeClient) Close() error {
	c.closeCount.Add(1)
	return nil
}

func TestOutboundClientLifecycleAndGlobalReset(t *testing.T) {
	client := new(fakeNativeClient)
	outbound := new(Outbound)
	if err := outbound.Init(context.Background(), validClientConfig(), &fakeDNSClient{}); err != nil {
		t.Fatal(err)
	}
	outbound.factory = func(cronet.NaiveClientOptions) (nativeClient, error) {
		return client, nil
	}
	first, err := outbound.ensureClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := outbound.ensureClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected one shared client per outbound")
	}

	CloseAllConnections()
	if client.resetCount.Load() != 1 {
		t.Fatalf("reset count = %d, want 1", client.resetCount.Load())
	}
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	if client.closeCount.Load() != 1 {
		t.Fatalf("close count = %d, want 1", client.closeCount.Load())
	}
	CloseAllConnections()
	if client.resetCount.Load() != 1 {
		t.Fatal("closed outbound remained registered")
	}
}

func TestOutboundCachesInitializationFailure(t *testing.T) {
	outbound := new(Outbound)
	if err := outbound.Init(context.Background(), validClientConfig(), &fakeDNSClient{}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	outbound.factory = func(cronet.NaiveClientOptions) (nativeClient, error) {
		calls.Add(1)
		return nil, errors.New("factory failed")
	}
	if _, err := outbound.ensureClient(nil); err == nil {
		t.Fatal("expected initialization error")
	}
	if _, err := outbound.ensureClient(nil); err == nil {
		t.Fatal("expected cached initialization error")
	}
	if calls.Load() != 1 {
		t.Fatalf("factory called %d times, want 1", calls.Load())
	}
}

func TestOpenUoTPacketConnSelectsProtocolVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint32
		expected string
	}{
		{name: "default v2", version: 0, expected: "sp.v2.udp-over-tcp.arpa"},
		{name: "v1", version: 1, expected: "sp.udp-over-tcp.arpa"},
		{name: "v2", version: 2, expected: "sp.v2.udp-over-tcp.arpa"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := new(recordingNativeClient)
			packetConn, err := openUoTPacketConn(
				context.Background(),
				client,
				M.ParseSocksaddrHostPort("1.1.1.1", 53),
				test.version,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer packetConn.Close()
			defer client.peer.Close()
			if client.destination.Fqdn != test.expected {
				t.Fatalf("UoT destination = %q, want %q", client.destination.Fqdn, test.expected)
			}
		})
	}
}
