package naive

import (
	"net/url"
	"strings"

	"github.com/sagernet/cronet-go"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/http/httpguts"
)

var reservedExtraHeaders = map[string]struct{}{
	"-connect-authority":     {},
	"-force-quic":            {},
	"-network-isolation-key": {},
	"connection":             {},
	"content-length":         {},
	"host":                   {},
	"keep-alive":             {},
	"padding":                {},
	"proxy-authenticate":     {},
	"proxy-authorization":    {},
	"proxy-connection":       {},
	"te":                     {},
	"trailer":                {},
	"transfer-encoding":      {},
	"upgrade":                {},
}

func ValidateConfig(config *ClientConfig) error {
	if config == nil {
		return errors.New("naive: missing client config")
	}
	if config.Address == nil || config.Address.AsAddress() == nil || strings.TrimSpace(config.Address.AsAddress().String()) == "" {
		return errors.New("naive: server address is required")
	}
	if config.Port == 0 || config.Port > 65535 {
		return errors.New("naive: server port must be between 1 and 65535")
	}
	if config.InsecureConcurrency == 0 {
		return errors.New("naive: insecure concurrency must be at least 1")
	}
	if config.Quic && config.InsecureConcurrency != 1 {
		return errors.New("naive: QUIC requires insecure concurrency to be 1")
	}
	if _, err := NormalizeQUICCongestionControl(config.QuicCongestionControl); err != nil {
		return err
	}
	for name, value := range config.ExtraHeaders {
		lowerName := strings.ToLower(strings.TrimSpace(name))
		if !httpguts.ValidHeaderFieldName(name) {
			return errors.New("naive: invalid extra header name: ", name)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return errors.New("naive: invalid extra header value for ", name)
		}
		if _, reserved := reservedExtraHeaders[lowerName]; reserved {
			return errors.New("naive: extra header is reserved: ", name)
		}
	}
	if udp := config.UdpOverTcp; udp != nil && udp.Enabled && udp.Version != 1 && udp.Version != 2 {
		return errors.New("naive: UDP over TCP version must be 1 or 2")
	}
	if tlsConfig := config.Tls; tlsConfig != nil && tlsConfig.Ech != nil && tlsConfig.Ech.Enabled {
		ech := tlsConfig.Ech
		if len(ech.ConfigList) == 0 {
			if err := validateDoHURL(ech.DnsServer); err != nil {
				return err
			}
		}
	}
	return nil
}

func NormalizeQUICCongestionControl(value string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "":
		return string(cronet.QUICCongestionControlDefault), nil
	case "BBR", "TBBR":
		return string(cronet.QUICCongestionControlBBR), nil
	case "BBR2", "BBRV2", "B2ON":
		return string(cronet.QUICCongestionControlBBRv2), nil
	case "CUBIC", "QBIC":
		return string(cronet.QUICCongestionControlCubic), nil
	case "RENO":
		return string(cronet.QUICCongestionControlReno), nil
	default:
		return "", errors.New("naive: unknown QUIC congestion control: ", value)
	}
}

func validateDoHURL(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("naive: ECH requires a fixed config or DNS over HTTPS server")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("naive: invalid DNS over HTTPS URL")
	}
	return nil
}
