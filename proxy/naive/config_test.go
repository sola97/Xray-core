package naive

import (
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func validClientConfig() *ClientConfig {
	return &ClientConfig{
		Address:             xnet.NewIPOrDomain(xnet.DomainAddress("naive.example.com")),
		Port:                443,
		InsecureConcurrency: 1,
		UdpOverTcp:          &UDPOverTCPConfig{Enabled: true, Version: 2},
		Tls:                 &TLSConfig{ServerName: "naive.example.com"},
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*ClientConfig)
		wantError string
	}{
		{name: "valid"},
		{name: "missing address", mutate: func(c *ClientConfig) { c.Address = nil }, wantError: "server address"},
		{name: "missing port", mutate: func(c *ClientConfig) { c.Port = 0 }, wantError: "server port"},
		{name: "zero concurrency", mutate: func(c *ClientConfig) { c.InsecureConcurrency = 0 }, wantError: "concurrency"},
		{name: "quic concurrency", mutate: func(c *ClientConfig) { c.Quic = true; c.InsecureConcurrency = 2 }, wantError: "QUIC requires"},
		{name: "unknown congestion control", mutate: func(c *ClientConfig) { c.QuicCongestionControl = "vegas" }, wantError: "unknown QUIC"},
		{name: "reserved header", mutate: func(c *ClientConfig) { c.ExtraHeaders = map[string]string{"Proxy-Authorization": "secret"} }, wantError: "reserved"},
		{name: "header newline", mutate: func(c *ClientConfig) { c.ExtraHeaders = map[string]string{"X-Test": "one\r\ntwo"} }, wantError: "header value"},
		{name: "unknown uot version", mutate: func(c *ClientConfig) { c.UdpOverTcp.Version = 3 }, wantError: "version"},
		{name: "dynamic ech missing doh", mutate: func(c *ClientConfig) { c.Tls.Ech = &ECHConfig{Enabled: true} }, wantError: "fixed config"},
		{name: "dynamic ech invalid doh", mutate: func(c *ClientConfig) {
			c.Tls.Ech = &ECHConfig{Enabled: true, DnsServer: "http://dns.example/dns-query"}
		}, wantError: "invalid DNS"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validClientConfig()
			if test.mutate != nil {
				test.mutate(config)
			}
			err := ValidateConfig(config)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestNormalizeQUICCongestionControl(t *testing.T) {
	tests := map[string]string{
		"":      "",
		"bbr":   "TBBR",
		"bbrv2": "B2ON",
		"cubic": "QBIC",
		"reno":  "RENO",
	}
	for input, expected := range tests {
		actual, err := NormalizeQUICCongestionControl(input)
		if err != nil {
			t.Fatalf("normalize %q: %v", input, err)
		}
		if actual != expected {
			t.Fatalf("normalize %q: got %q, want %q", input, actual, expected)
		}
	}
}
