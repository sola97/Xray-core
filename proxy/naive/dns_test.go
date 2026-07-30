package naive

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
)

type fakeDNSClient struct {
	ips       []xnet.IP
	ttl       uint32
	err       error
	lastName  string
	lastQuery featuredns.IPOption
}

func (*fakeDNSClient) Start() error      { return nil }
func (*fakeDNSClient) Close() error      { return nil }
func (*fakeDNSClient) Type() interface{} { return featuredns.ClientType() }

func (c *fakeDNSClient) LookupIP(domain string, option featuredns.IPOption) ([]xnet.IP, uint32, error) {
	c.lastName = domain
	c.lastQuery = option
	return c.ips, c.ttl, c.err
}

func TestDNSResolverUsesXrayDNS(t *testing.T) {
	client := &fakeDNSClient{
		ips: []xnet.IP{xnet.ParseIP("192.0.2.10"), xnet.ParseIP("2001:db8::10")},
		ttl: 123,
	}
	resolver, err := newDNSResolver(client, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	request := new(dns.Msg)
	request.SetQuestion("naive.example.com.", dns.TypeA)
	response := resolver(context.Background(), request)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("unexpected response: %v", response)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != "192.0.2.10" || answer.Hdr.Ttl != 123 {
		t.Fatalf("unexpected A answer: %v", response.Answer[0])
	}
	if client.lastName != "naive.example.com" || !client.lastQuery.IPv4Enable || client.lastQuery.IPv6Enable {
		t.Fatalf("unexpected lookup: name=%q option=%+v", client.lastName, client.lastQuery)
	}

	request.SetQuestion("naive.example.com.", dns.TypeAAAA)
	response = resolver(context.Background(), request)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("unexpected response: %v", response)
	}
	if answer, ok := response.Answer[0].(*dns.AAAA); !ok || answer.AAAA.String() != "2001:db8::10" {
		t.Fatalf("unexpected AAAA answer: %v", response.Answer[0])
	}
}

func TestDNSResolverRejectsUnsupportedQueryWithoutDoH(t *testing.T) {
	resolver, err := newDNSResolver(&fakeDNSClient{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("naive.example.com.", dns.TypeHTTPS)
	response := resolver(context.Background(), request)
	if response.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("got rcode %d, want %d", response.Rcode, dns.RcodeNotImplemented)
	}
}
