package conf_test

import (
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/naive"
	"google.golang.org/protobuf/proto"
)

func TestNaiveClientConfigParsing(t *testing.T) {
	creator := func() Buildable { return new(NaiveClientConfig) }
	runMultiTestCase(t, []TestCase{{
		Input: `{
			"address": "naive.example.com",
			"port": 443,
			"username": "user",
			"password": "password",
			"insecureConcurrency": 2,
			"extraHeaders": {"X-Test": "enabled"},
			"udpOverTcp": {"enabled": true},
			"quicCongestionControl": "bbr",
			"tls": {"serverName": "front.example.com"}
		}`,
		Parser: loadJSON(creator),
		Output: &naive.ClientConfig{
			Address:               xnet.NewIPOrDomain(xnet.DomainAddress("naive.example.com")),
			Port:                  443,
			Username:              "user",
			Password:              "password",
			InsecureConcurrency:   2,
			ExtraHeaders:          map[string]string{"X-Test": "enabled"},
			UdpOverTcp:            &naive.UDPOverTCPConfig{Enabled: true, Version: 2},
			QuicCongestionControl: "TBBR",
			Tls:                   &naive.TLSConfig{ServerName: "front.example.com"},
		},
	}})
}

func TestNaiveClientConfigECHPEM(t *testing.T) {
	configBytes := []byte{0, 4, 1, 2, 3, 4}
	config := &NaiveClientConfig{
		Address:             &Address{Address: xnet.DomainAddress("naive.example.com")},
		Port:                443,
		InsecureConcurrency: 1,
		TLS: &NaiveTLSConfig{ECH: &NaiveECHConfig{
			Enabled: true,
			Config:  []string{string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBytes}))},
		}},
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	expected := &naive.ClientConfig{
		Address:             xnet.NewIPOrDomain(xnet.DomainAddress("naive.example.com")),
		Port:                443,
		InsecureConcurrency: 1,
		Tls:                 &naive.TLSConfig{Ech: &naive.ECHConfig{Enabled: true, ConfigList: configBytes}},
	}
	if !proto.Equal(built, expected) {
		t.Fatalf("built config = %v, want %v", built, expected)
	}
}

func TestNaiveClientConfigRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError string
	}{
		{name: "quic concurrency", input: `{"address":"example.com","port":443,"insecureConcurrency":2,"quic":true}`, wantError: "QUIC requires"},
		{name: "reserved header", input: `{"address":"example.com","port":443,"insecureConcurrency":1,"extraHeaders":{"Padding":"x"}}`, wantError: "reserved"},
		{name: "reserved host header", input: `{"address":"example.com","port":443,"insecureConcurrency":1,"extraHeaders":{"Host":"front.example.com"}}`, wantError: "reserved"},
		{name: "invalid uot", input: `{"address":"example.com","port":443,"insecureConcurrency":1,"udpOverTcp":{"enabled":true,"version":3}}`, wantError: "version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := new(NaiveClientConfig)
			if err := json.Unmarshal([]byte(test.input), config); err != nil {
				t.Fatal(err)
			}
			_, err := config.Build()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestNaiveOutboundRegistration(t *testing.T) {
	input := `{
		"protocol": "naive",
		"tag": "proxy",
		"settings": {
			"address": "naive.example.com",
			"port": 443,
			"insecureConcurrency": 1,
			"udpOverTcp": {"enabled": true, "version": 2},
			"tls": {"serverName": "naive.example.com"}
		},
		"mux": {"enabled": false, "concurrency": -1}
	}`
	config := new(OutboundDetourConfig)
	if err := json.Unmarshal([]byte(input), config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	naiveConfig, ok := instance.(*naive.ClientConfig)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *naive.ClientConfig", instance)
	}
	if naiveConfig.UdpOverTcp == nil || !naiveConfig.UdpOverTcp.Enabled || naiveConfig.UdpOverTcp.Version != 2 {
		t.Fatalf("unexpected UoT config: %+v", naiveConfig.UdpOverTcp)
	}
}
