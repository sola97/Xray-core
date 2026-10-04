package naive

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
)

type handshakeConn struct {
	net.Conn
	stall  bool
	err    error
	closed chan struct{}
	once   sync.Once
	writes atomic.Int32
}

func newHandshakeConn(stall bool, err error) *handshakeConn {
	return &handshakeConn{stall: stall, err: err, closed: make(chan struct{})}
}

func (c *handshakeConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *handshakeConn) HandshakeContext(ctx context.Context) error {
	if c.stall {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closed:
			return net.ErrClosed
		}
	}
	return c.err
}

func (c *handshakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *handshakeConn) Write(data []byte) (int, error) {
	c.writes.Add(1)
	return len(data), nil
}

type handshakeClient struct {
	fakeNativeClient
	mu          sync.Mutex
	connections []*handshakeConn
	calls       int
}

func (c *handshakeClient) DialEarly(context.Context, M.Socksaddr) (cronet.NaiveConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls >= len(c.connections) {
		return nil, errors.New("unexpected additional dial")
	}
	conn := c.connections[c.calls]
	c.calls++
	return conn, nil
}

func testConnectionDialer(client *handshakeClient) *connectionDialer {
	outbound := &Outbound{client: client}
	return &connectionDialer{client: client, outbound: outbound, timeout: 20 * time.Millisecond}
}

func TestConnectionRecoversStalledHandshakeBeforePayload(t *testing.T) {
	stale := newHandshakeConn(true, nil)
	fresh := newHandshakeConn(false, nil)
	client := &handshakeClient{connections: []*handshakeConn{stale, fresh}}
	dialer := testConnectionDialer(client)
	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if client.calls != 2 || client.resetCount.Load() != 1 {
		t.Fatalf("dials=%d resets=%d", client.calls, client.resetCount.Load())
	}
	select {
	case <-stale.closed:
	default:
		t.Fatal("stalled attempt was not closed")
	}
	if stale.writes.Load() != 0 || fresh.writes.Load() != 0 {
		t.Fatal("application payload sent during retry")
	}
}

func TestConnectionRejectsWithoutPoolResetOrRetry(t *testing.T) {
	rejected := errors.New("unexpected response status: 407")
	client := &handshakeClient{connections: []*handshakeConn{newHandshakeConn(false, rejected)}}
	_, err := testConnectionDialer(client).DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443"))
	if !errors.Is(err, rejected) {
		t.Fatalf("error=%v", err)
	}
	if client.calls != 1 || client.resetCount.Load() != 0 {
		t.Fatal("rejection was retried or cleared other connections")
	}
}

func TestConnectionCallerDeadlineDoesNotResetPool(t *testing.T) {
	conn := newHandshakeConn(true, nil)
	client := &handshakeClient{connections: []*handshakeConn{conn}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := testConnectionDialer(client).DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if client.calls != 1 || client.resetCount.Load() != 0 {
		t.Fatal("caller cancellation reset pool or retried")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("cancelled stream not closed")
	}
}

func TestConnectionLifetimeUsesCallerNotHandshakeDeadline(t *testing.T) {
	raw := newHandshakeConn(false, nil)
	client := &handshakeClient{connections: []*handshakeConn{raw}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := testConnectionDialer(client).DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(40 * time.Millisecond)
	select {
	case <-raw.closed:
		t.Fatal("successful stream closed when handshake budget ended")
	default:
	}
	cancel()
	select {
	case <-raw.closed:
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not close established stream")
	}
}

func TestConnectionRetryIsBounded(t *testing.T) {
	first := newHandshakeConn(true, nil)
	second := newHandshakeConn(true, nil)
	client := &handshakeClient{connections: []*handshakeConn{first, second}}
	_, err := testConnectionDialer(client).DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if client.calls != 2 || client.resetCount.Load() != 1 {
		t.Fatalf("dials=%d resets=%d", client.calls, client.resetCount.Load())
	}
	select {
	case <-second.closed:
	default:
		t.Fatal("failed retry stream leaked")
	}
}

func TestConnectionExplicitCloseStopsCancellationHook(t *testing.T) {
	raw := newHandshakeConn(false, nil)
	client := &handshakeClient{connections: []*handshakeConn{raw}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := testConnectionDialer(client).DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.(*contextConn).stopCancel() {
		t.Fatal("explicit Close left the cancellation hook registered")
	}
}

func TestConnectionAlreadyCancelledDoesNotDial(t *testing.T) {
	client := new(handshakeClient)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := testConnectionDialer(client).DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if client.calls != 0 || client.resetCount.Load() != 0 {
		t.Fatal("cancelled request dialled or cleared the pool")
	}
}

func TestConnectionConcurrentRefreshIsCoalesced(t *testing.T) {
	client := new(fakeNativeClient)
	outbound := &Outbound{client: client}
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() { defer group.Done(); outbound.refreshConnections(client) }()
	}
	group.Wait()
	if client.resetCount.Load() != 1 {
		t.Fatalf("resets=%d", client.resetCount.Load())
	}
	outbound.closed = true
	if outbound.refreshConnections(client) {
		t.Fatal("closed outbound refreshed")
	}
}
