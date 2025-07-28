package chinadns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var defaultDNSServerList = []string{
	"8.8.8.8:domain",
	"8.8.4.4:domain",
	"4.2.2.1:domain",
	"4.2.2.2:domain",
	"4.2.2.3:domain",
	"4.2.2.4:domain",
	"4.2.2.5:domain",
	"4.2.2.6:domain",
	"101.101.101.101:domain",
	"101.102.103.104:domain",
	"1.1.1.1:domain",
	"1.0.0.1:domain",
	"9.9.9.9:domain",
	"45.11.45.11:domain",
	"149.112.112.112:domain",
	"208.67.222.222:domain",
	"208.67.220.220:domain",
	"208.67.222.220:domain",
	"208.67.220.222:domain",
	"208.67.222.123:domain",
	"208.67.220.123:domain",
	"8.26.56.26:domain",
	"8.20.247.20:domain",
	"64.6.64.6:domain",
	"64.6.65.6:domain",
	"156.154.70.2:domain",
	"156.154.71.2:domain",
	"156.154.70.3:domain",
	"156.154.71.3:domain",
	"94.140.14.14:domain",
	"94.140.15.15:domain",
	"94.140.14.140:domain",
	"94.140.14.141:domain",
	"94.140.14.15:domain",
	"94.140.15.16:domain",
	"[2001:4860:4860::8888]:domain",
	"[2001:4860:4860::8844]:domain",
	"[2001:de4::101]:domain",
	"[2001:de4::102]:domain",
	"[2606:4700:4700::1111]:domain",
	"[2606:4700:4700::1001]:domain",
	"[2620:fe::fe]:domain",
	"[2620:fe::9]:domain",
	"[2a09::]:domain",
	"[2a11::]:domain",
	"[2620:119:35::35]:domain",
	"[2620:119:53::53]:domain",
	"[2620:119:35::123]:domain",
	"[2620:119:53::123]:domain",
	"[2620:74:1b::1:1]:domain",
	"[2620:74:1c::2:2]:domain",
	"[2610:a1:1018::2]:domain",
	"[2610:a1:1019::2]:domain",
	"[2610:a1:1018::3]:domain",
	"[2610:a1:1019::3]:domain",
	"[2a10:50c0::ad1:ff]:domain",
	"[2a10:50c0::ad2:ff]:domain",
	"[2a10:50c0::1:ff]:domain",
	"[2a10:50c0::2:ff]:domain",
	"[2a10:50c0::bad1:ff]:domain",
	"[2a10:50c0::bad2:ff]:domain",
}

type Config struct {
	// The network can be "ip", "ip4"(IPv4-only) or "ip6"(IPv6-only)
	// Outside of the above list, the value of the network is "ip".
	Network string

	// Single query timeout, Default is 2
	Timeout int

	ServerList []string
}

type ChinaResolver struct {
	// The network can be "ip", "ip4"(IPv4-only) or "ip6"(IPv6-only)
	// Outside of the above list, the value of the network is "ip".
	network string

	// Single query timeout, Default is 2
	timeout int

	serverList []string
}

func (r *ChinaResolver) appendServerList(host string, port string) {
	server := net.JoinHostPort(host, port)
	r.serverList = append(r.serverList, server)
}

func (r *ChinaResolver) setServerList(servers []string) {
	for _, server := range servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			// The server without port should OK
			// Try add :domain, parse again
			serverWithDomain := net.JoinHostPort(host, "domain")
			host, port, err = net.SplitHostPort(serverWithDomain)
		}
		if err != nil {
			continue
		}
		// The host must be a literal IP address or a literal IPv6 address
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		r.appendServerList(host, port)
	}
}

func (r *ChinaResolver) applyConfig(config *Config) {
	r.setServerList(config.ServerList)
	r.network = config.Network
	r.timeout = config.Timeout
}

func (r *ChinaResolver) buildDNSQueryWithOPT(typ dnsmessage.Type, name string) ([]byte, error) {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return nil, err
	}
	var txID uint16 = binary.LittleEndian.Uint16(b[:])
	var buf []byte
	var pkt []byte
	var fqdn string = fmt.Sprintf("%s.", name)
	m := dnsmessage.NewBuilder(buf, dnsmessage.Header{
		ID:               txID,
		RecursionDesired: true,
	})
	err = m.StartQuestions()
	if err != nil {
		return nil, err
	}

	err = m.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(fqdn),
		Type:  typ,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, err
	}
	err = m.StartAdditionals()
	if err != nil {
		return nil, err
	}

	// In Chinese mainland, DNS responses injected by
	// middleboxes do not process the OPT part,
	// even if the requester sends the OPT portion.
	// It has been observed that almost all DNS servers
	// handle the OPT part, which
	// we add in preparation for subsequent identification.
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}

	var cookie = make([]byte, 8)
	_, err = rand.Read(cookie[:])
	if err != nil {
		return nil, err
	}

	// Make the fingerprint of the query packet
	// exactly the same as the dig.
	if err := m.OPTResource(rh,
		dnsmessage.OPTResource{
			Options: []dnsmessage.Option{
				{Code: 10, Data: cookie},
			}}); err != nil {
		return nil, err
	}

	pkt, err = m.Finish()
	if err != nil {
		return nil, err
	}
	return pkt, nil
}

func (r *ChinaResolver) filterResult(payload []byte) ([]string, bool) {
	var p dnsmessage.Parser
	var addrs []string
	_, err := p.Start(payload)
	if err != nil {
		return nil, false
	}
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, false
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, false
		}
		switch h.Type {
		case dnsmessage.TypeA:
			arec, err := p.AResource()
			if err != nil {
				return nil, false
			}
			ip := net.IP(arec.A[:])
			var addr = ip.String()
			if addr == "<nil>" {
				return nil, false
			}
			addrs = append(addrs, addr)
		case dnsmessage.TypeAAAA:
			arec, err := p.AAAAResource()
			if err != nil {
				return nil, false
			}
			ip := net.IP(arec.AAAA[:])
			var addr = ip.String()
			if addr == "<nil>" {
				return nil, false
			}
			addrs = append(addrs, addr)
		default:
			p.SkipAnswer()
		}
	}
	p.SkipAllAuthorities()
	_, err = p.AdditionalHeader()
	if err != nil {
		return nil, false
	}
	// Found OPT
	return addrs, true
}

func (r *ChinaResolver) lookupIP(typ dnsmessage.Type, name string) ([]string, error) {
	if r.serverList == nil || len(r.serverList) == 0 {
		r.serverList = defaultDNSServerList
	}
	if r.timeout <= 0 {
		r.timeout = 2
	}
	var timeout = r.timeout
	payload, err := r.buildDNSQueryWithOPT(typ, name)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, server := range r.serverList {
		conn, err := net.Dial("udp", server)
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		_, err = conn.Write(payload)
		if err != nil {
			break
		}
		// Receive UDP until you obtain a response
		// that is not a middlebox injection.
		for {
			response := make([]byte, 512)
			n, err := conn.Read(response)
			// Connection lost....
			if err != nil {
				break
			}
			resp := response[:n]
			result, ok := r.filterResult(resp)
			if ok {
				results = result
				break
			}
		}
		// Exit when you get correct IP
		if results != nil {
			break
		}
	}
	if results == nil {
		return nil, fmt.Errorf("Lookup IP Failed,no reult")
	}
	return results, nil
}

func (r *ChinaResolver) LookupIP(name string) ([]string, error) {
	switch r.network {
	case "ip4":
		return r.lookupIP(dnsmessage.TypeA, name)
	case "ip6":
		return r.lookupIP(dnsmessage.TypeAAAA, name)
	default:
		ip4, err4 := r.lookupIP(dnsmessage.TypeA, name)
		ip6, err6 := r.lookupIP(dnsmessage.TypeAAAA, name)
		if err4 == nil || err6 == nil {
			return append(ip4, ip6...), nil
		}
	}
	return nil, nil
}

func (r *ChinaResolver) LookupIP4(name string) ([]string, error) {
	return r.lookupIP(dnsmessage.TypeA, name)
}

func (r *ChinaResolver) LookupIP6(name string) ([]string, error) {
	return r.lookupIP(dnsmessage.TypeAAAA, name)
}

func Client(config *Config) *ChinaResolver {
	client := &ChinaResolver{}
	client.applyConfig(config)
	return client
}
