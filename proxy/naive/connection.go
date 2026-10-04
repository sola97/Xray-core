package naive

import (
	"context"
	stderrors "errors"
	"net"
	"os"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/errors"
)

const connectTimeout = 5 * time.Second

// connectionDialer bounds CONNECT before forwarding caller payload. A timed-out
// pooled session is cleared once, then one fresh attempt is allowed.
type connectionDialer struct {
	client   nativeClient
	outbound *Outbound
	timeout  time.Duration
}

func (d *connectionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := d.connect(ctx, destination)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt != 0 || !stderrors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("naive: CONNECT failed").Base(err)
		}
		if d.outbound.refreshConnections(d.client) {
			errors.LogWarning(ctx, "naive: CONNECT timed out; cleared pooled connections")
		}
	}
}

func (d *connectionDialer) connect(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	raw, err := d.client.DialEarly(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn := &contextConn{Conn: raw}
	// Cronet's read/write wait paths do not observe ctx.Done themselves.
	conn.stopCancel = context.AfterFunc(ctx, func() { _ = raw.Close() })
	if err := raw.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (*connectionDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type contextConn struct {
	net.Conn
	stopCancel func() bool
}

func (c *contextConn) Close() error {
	c.stopCancel()
	return c.Conn.Close()
}

func (o *Outbound) refreshConnections(client nativeClient) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.client != client || time.Since(o.lastConnectionReset) < connectTimeout {
		return false
	}
	o.lastConnectionReset = time.Now()
	client.CloseAllConnections()
	return true
}
