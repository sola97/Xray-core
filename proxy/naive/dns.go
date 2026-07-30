package naive

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/errors"
	featuredns "github.com/xtls/xray-core/features/dns"
)

const maxDoHResponseSize = 64 * 1024

type resolver struct {
	client     featuredns.Client
	dohURL     string
	httpClient *http.Client
}

func newDNSResolver(client featuredns.Client, dialer N.Dialer, dohURL string) (cronet.DNSResolverFunc, error) {
	r := &resolver{client: client, dohURL: dohURL}
	if dohURL != "" {
		if err := validateDoHURL(dohURL); err != nil {
			return nil, err
		}
		transport := &http.Transport{
			Proxy:               nil,
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext: func(ctx context.Context, network, address string) (stdnet.Conn, error) {
				destination := M.ParseSocksaddr(address)
				if !destination.IsValid() {
					return nil, errors.New("naive: invalid DNS over HTTPS destination")
				}
				return dialer.DialContext(ctx, network, destination)
			},
		}
		r.httpClient = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	}
	return r.resolve, nil
}

func (r *resolver) resolve(ctx context.Context, request *dns.Msg) *dns.Msg {
	if request == nil || len(request.Question) == 0 {
		return dnsErrorResponse(request, dns.RcodeFormatError)
	}
	question := request.Question[0]
	switch question.Qtype {
	case dns.TypeA:
		return r.lookupIP(request, strings.TrimSuffix(question.Name, "."), true, false)
	case dns.TypeAAAA:
		return r.lookupIP(request, strings.TrimSuffix(question.Name, "."), false, true)
	case dns.TypeHTTPS:
		if r.httpClient == nil {
			return dnsErrorResponse(request, dns.RcodeNotImplemented)
		}
		return r.resolveDoH(ctx, request)
	default:
		return dnsErrorResponse(request, dns.RcodeNotImplemented)
	}
}

func (r *resolver) lookupIP(request *dns.Msg, domain string, ipv4, ipv6 bool) *dns.Msg {
	ips, ttl, err := r.client.LookupIP(domain, featuredns.IPOption{IPv4Enable: ipv4, IPv6Enable: ipv6})
	if err != nil {
		rcode := featuredns.RCodeFromError(err)
		if rcode == 0 {
			rcode = dns.RcodeServerFailure
		}
		return dnsErrorResponse(request, int(rcode))
	}
	if ttl == 0 {
		ttl = featuredns.DefaultTTL
	}
	response := new(dns.Msg)
	response.SetReply(request)
	for _, ip := range ips {
		if ipv4 {
			if value := stdnet.IP(ip).To4(); value != nil {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   value,
				})
			}
			continue
		}
		if value := stdnet.IP(ip).To16(); value != nil && stdnet.IP(ip).To4() == nil {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: value,
			})
		}
	}
	return response
}

func (r *resolver) resolveDoH(ctx context.Context, request *dns.Msg) *dns.Msg {
	payload, err := request.Pack()
	if err != nil {
		return dnsErrorResponse(request, dns.RcodeFormatError)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohURL, bytes.NewReader(payload))
	if err != nil {
		return dnsErrorResponse(request, dns.RcodeServerFailure)
	}
	httpRequest.Header.Set("Accept", "application/dns-message")
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	response, err := r.httpClient.Do(httpRequest)
	if err != nil {
		errors.LogWarningInner(ctx, err, "naive: DNS over HTTPS query failed")
		return dnsErrorResponse(request, dns.RcodeServerFailure)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		errors.LogWarning(ctx, "naive: DNS over HTTPS returned HTTP status ", response.StatusCode)
		return dnsErrorResponse(request, dns.RcodeServerFailure)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDoHResponseSize+1))
	if err != nil || len(body) > maxDoHResponseSize {
		return dnsErrorResponse(request, dns.RcodeServerFailure)
	}
	dnsResponse := new(dns.Msg)
	if err := dnsResponse.Unpack(body); err != nil {
		return dnsErrorResponse(request, dns.RcodeServerFailure)
	}
	dnsResponse.Id = request.Id
	return dnsResponse
}

func dnsErrorResponse(request *dns.Msg, rcode int) *dns.Msg {
	response := new(dns.Msg)
	if request != nil {
		response.SetReply(request)
	}
	response.Response = true
	response.Rcode = rcode
	return response
}
