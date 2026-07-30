package conf

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/naive"
	"google.golang.org/protobuf/proto"
)

type NaiveUDPOverTCPConfig struct {
	Enabled bool   `json:"enabled"`
	Version uint32 `json:"version"`
}

type NaiveECHConfig struct {
	Enabled         bool     `json:"enabled"`
	Config          []string `json:"config"`
	QueryServerName string   `json:"queryServerName"`
	DNSServer       string   `json:"dnsServer"`
}

type NaiveTLSConfig struct {
	ServerName  string          `json:"serverName"`
	Certificate []string        `json:"certificate"`
	ECH         *NaiveECHConfig `json:"ech"`
}

type NaiveClientConfig struct {
	Address               *Address               `json:"address"`
	Port                  uint32                 `json:"port"`
	Username              string                 `json:"username"`
	Password              string                 `json:"password"`
	InsecureConcurrency   uint32                 `json:"insecureConcurrency"`
	ExtraHeaders          map[string]string      `json:"extraHeaders"`
	UDPOverTCP            *NaiveUDPOverTCPConfig `json:"udpOverTcp"`
	QUIC                  bool                   `json:"quic"`
	QUICCongestionControl string                 `json:"quicCongestionControl"`
	TLS                   *NaiveTLSConfig        `json:"tls"`
}

func (c *NaiveClientConfig) Build() (proto.Message, error) {
	if c.Address == nil || c.Address.Address == nil || strings.TrimSpace(c.Address.Address.String()) == "" {
		return nil, errors.New("naive: server address is required")
	}
	concurrency := c.InsecureConcurrency
	if concurrency == 0 {
		concurrency = 1
	}
	congestionControl, err := naive.NormalizeQUICCongestionControl(c.QUICCongestionControl)
	if err != nil {
		return nil, err
	}
	config := &naive.ClientConfig{
		Address:               c.Address.Build(),
		Port:                  c.Port,
		Username:              c.Username,
		Password:              c.Password,
		InsecureConcurrency:   concurrency,
		ExtraHeaders:          c.ExtraHeaders,
		Quic:                  c.QUIC,
		QuicCongestionControl: congestionControl,
	}
	if c.UDPOverTCP != nil {
		version := c.UDPOverTCP.Version
		if c.UDPOverTCP.Enabled && version == 0 {
			version = 2
		}
		config.UdpOverTcp = &naive.UDPOverTCPConfig{Enabled: c.UDPOverTCP.Enabled, Version: version}
	}
	if c.TLS != nil {
		trustedRoots, err := parseTrustedRoots(c.TLS.Certificate)
		if err != nil {
			return nil, err
		}
		config.Tls = &naive.TLSConfig{
			ServerName:              c.TLS.ServerName,
			TrustedRootCertificates: trustedRoots,
		}
		if c.TLS.ECH != nil {
			echConfig, err := parseECHConfig(c.TLS.ECH.Config)
			if err != nil {
				return nil, err
			}
			config.Tls.Ech = &naive.ECHConfig{
				Enabled:         c.TLS.ECH.Enabled,
				ConfigList:      echConfig,
				QueryServerName: c.TLS.ECH.QueryServerName,
				DnsServer:       c.TLS.ECH.DNSServer,
			}
		}
	}
	if err := naive.ValidateConfig(config); err != nil {
		return nil, err
	}
	return config, nil
}

func parseTrustedRoots(certificates []string) (string, error) {
	if len(certificates) == 0 {
		return "", nil
	}
	pool := x509.NewCertPool()
	var builder strings.Builder
	for _, certificate := range certificates {
		if strings.TrimSpace(certificate) == "" {
			continue
		}
		data := []byte(certificate)
		if !pool.AppendCertsFromPEM(data) {
			return "", errors.New("naive: invalid trusted CA certificate PEM")
		}
		builder.Write(data)
		if !strings.HasSuffix(certificate, "\n") {
			builder.WriteByte('\n')
		}
	}
	return builder.String(), nil
}

func parseECHConfig(values []string) ([]byte, error) {
	var config []byte
	blockCount := 0
	for _, value := range values {
		rest := []byte(value)
		for len(strings.TrimSpace(string(rest))) > 0 {
			block, next := pem.Decode(rest)
			if block == nil || block.Type != "ECH CONFIGS" {
				return nil, errors.New("naive: invalid ECH config PEM")
			}
			blockCount++
			if blockCount > 1 {
				return nil, errors.New("naive: ECH config must contain exactly one ECH CONFIGS block")
			}
			config = append(config, block.Bytes...)
			rest = next
		}
	}
	return config, nil
}
