package naive

import (
	"context"
	stderrors "errors"
	stdnet "net"
	"sync"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type nativeClient interface {
	N.Dialer
	DialEarly(context.Context, M.Socksaddr) (cronet.NaiveConn, error)
	CloseAllConnections()
	Close() error
}

type cronetClient struct {
	*cronet.NaiveClient
}

func (c *cronetClient) CloseAllConnections() {
	c.Engine().CloseAllConnections()
}

type clientFactory func(cronet.NaiveClientOptions) (nativeClient, error)

type Outbound struct {
	ctx       context.Context
	config    *ClientConfig
	dnsClient featuredns.Client
	factory   clientFactory

	initOnce sync.Once
	initErr  error
	mu       sync.Mutex
	client   nativeClient
	closed   bool
}

var activeOutbounds sync.Map

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		outbound := new(Outbound)
		if err := core.RequireFeatures(ctx, func(dnsClient featuredns.Client) error {
			return outbound.Init(ctx, config.(*ClientConfig), dnsClient)
		}); err != nil {
			return nil, err
		}
		return outbound, nil
	}))
}

func (o *Outbound) Init(ctx context.Context, config *ClientConfig, dnsClient featuredns.Client) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	o.ctx = ctx
	o.config = config
	o.dnsClient = dnsClient
	o.factory = startCronetClient
	return nil
}

func startCronetClient(options cronet.NaiveClientOptions) (nativeClient, error) {
	client, err := cronet.NewNaiveClient(options)
	if err != nil {
		return nil, errors.New("naive: create Cronet client").Base(err)
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return nil, errors.New("naive: start Cronet engine").Base(err)
	}
	return &cronetClient{NaiveClient: client}, nil
}

func (o *Outbound) ensureClient(dialer internet.Dialer) (nativeClient, error) {
	o.initOnce.Do(func() {
		o.mu.Lock()
		if o.closed {
			o.mu.Unlock()
			o.initErr = stdnet.ErrClosed
			return
		}
		o.mu.Unlock()

		xrayDialer := singbridge.NewDialer(dialer)
		dohURL := ""
		if o.config.Tls != nil && o.config.Tls.Ech != nil {
			dohURL = o.config.Tls.Ech.DnsServer
		}
		resolver, err := newDNSResolver(o.dnsClient, xrayDialer, dohURL)
		if err != nil {
			o.initErr = err
			return
		}

		serverName := ""
		trustedRoots := ""
		var echEnabled bool
		var echConfigList []byte
		var echQueryServerName string
		if tlsConfig := o.config.Tls; tlsConfig != nil {
			serverName = tlsConfig.ServerName
			trustedRoots = tlsConfig.TrustedRootCertificates
			if tlsConfig.Ech != nil {
				echEnabled = tlsConfig.Ech.Enabled
				echConfigList = tlsConfig.Ech.ConfigList
				echQueryServerName = tlsConfig.Ech.QueryServerName
			}
		}
		congestionControl, err := NormalizeQUICCongestionControl(o.config.QuicCongestionControl)
		if err != nil {
			o.initErr = err
			return
		}
		client, err := o.factory(cronet.NaiveClientOptions{
			Context:                 o.ctx,
			ServerAddress:           singbridge.ToSocksaddr(xnet.TCPDestination(o.config.Address.AsAddress(), xnet.Port(o.config.Port))),
			ServerName:              serverName,
			Username:                o.config.Username,
			Password:                o.config.Password,
			InsecureConcurrency:     int(o.config.InsecureConcurrency),
			ExtraHeaders:            o.config.ExtraHeaders,
			TrustedRootCertificates: trustedRoots,
			DNSResolver:             resolver,
			Logger:                  singbridge.NewLogger(newNaiveError),
			Dialer:                  xrayDialer,
			ECHEnabled:              echEnabled,
			ECHConfigList:           echConfigList,
			ECHQueryServerName:      echQueryServerName,
			QUIC:                    o.config.Quic,
			QUICCongestionControl:   cronet.QUICCongestionControl(congestionControl),
		})
		if err != nil {
			o.initErr = err
			return
		}

		o.mu.Lock()
		if o.closed {
			o.mu.Unlock()
			_ = client.Close()
			o.initErr = stdnet.ErrClosed
			return
		}
		o.client = client
		activeOutbounds.Store(o, struct{}{})
		o.mu.Unlock()
	})
	if o.initErr != nil {
		return nil, o.initErr
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client == nil {
		return nil, errors.New("naive: Cronet client was not initialized")
	}
	return o.client, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("naive: outbound session is missing")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("naive: target is not specified")
	}
	ob.Name = "naive"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	client, err := o.ensureClient(dialer)
	if err != nil {
		return err
	}
	errors.LogInfo(ctx, "naive: tunneling ", destination.Network.SystemString(), " request to ", destination)

	inbound := session.InboundFromContext(ctx)
	var inboundConn stdnet.Conn
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	if destination.Network == xnet.Network_TCP {
		serverConn, err := client.DialEarly(ctx, singbridge.ToSocksaddr(destination))
		if err != nil {
			return errors.New("naive: dial TCP target").Base(err)
		}
		defer serverConn.Close()
		return singbridge.CopyConn(ctx, inboundConn, link, serverConn)
	}
	if destination.Network != xnet.Network_UDP {
		return errors.New("naive: unsupported target network: ", destination.Network)
	}
	if o.config.UdpOverTcp == nil || !o.config.UdpOverTcp.Enabled {
		return errors.New("naive: UDP requires UDP over TCP")
	}
	version := o.config.UdpOverTcp.Version
	if version == 0 {
		version = uot.Version
	}
	serverConn, err := openUoTPacketConn(ctx, client, singbridge.ToSocksaddr(destination), version)
	if err != nil {
		return errors.New("naive: open UoT v", version, " packet connection").Base(err)
	}
	defer serverConn.Close()
	return singbridge.CopyPacketConn(ctx, inboundConn, link, destination, serverConn)
}

func openUoTPacketConn(ctx context.Context, client nativeClient, destination M.Socksaddr, version uint32) (stdnet.PacketConn, error) {
	if version == 0 {
		version = uot.Version
	}
	return (&uot.Client{Dialer: client, Version: uint8(version)}).ListenPacket(ctx, destination)
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	o.closed = true
	activeOutbounds.Delete(o)
	client := o.client
	o.client = nil
	o.mu.Unlock()
	if client == nil {
		return nil
	}
	if err := client.Close(); err != nil && !stderrors.Is(err, stdnet.ErrClosed) {
		return errors.New("naive: close Cronet client").Base(err)
	}
	return nil
}

func CloseAllConnections() {
	activeOutbounds.Range(func(key, _ interface{}) bool {
		outbound := key.(*Outbound)
		outbound.mu.Lock()
		client := outbound.client
		if client != nil {
			client.CloseAllConnections()
		}
		outbound.mu.Unlock()
		return true
	})
}

func newNaiveError(values ...any) *errors.Error {
	return errors.New(append([]any{"naive: "}, values...)...)
}
