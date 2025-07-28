package chinahttp

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	chinadns "github.com/excitedplus1s/gfwutils/dns"
	tls "github.com/excitedplus1s/utlscm"
)

type Config struct {
	ResolverCache     *map[string][]string
	AnticensorEnabled bool
}

type clientSelector struct {
	sync.RWMutex
	dnsConfig         *chinadns.Config
	resolverCache     *map[string][]string
	anticensorEnabled bool
}

func (c *clientSelector) applyConfig(dnsConfig *chinadns.Config, config *Config) {
	if config != nil {
		c.resolverCache = config.ResolverCache
		c.anticensorEnabled = config.AnticensorEnabled
	}
	c.dnsConfig = dnsConfig
}

func (c *clientSelector) Client() *http.Client {
	if c.anticensorEnabled {
		return &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, ok := getHostName(addr)
					if !ok {
						return nil, fmt.Errorf("getHostName() error: pasrse hostname failed.")
					}
					resolvedAddr, ok := c.selectAvailableIPAddr(addr)
					if !ok {
						return nil, fmt.Errorf("selectAvailableIPAddr() error: no available ip found.")
					}
					tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, resolvedAddr)
					if err != nil {
						return nil, err
					}
					config := tls.Config{
						ServerName:               host,
						MaxClientHelloRecordSize: 520,
					}
					tlsConn := tls.UClient(tcpConn, &config, tls.HelloGolang_Junk_Ext)

					err = tlsConn.Handshake()
					if err != nil {
						return nil, fmt.Errorf("uTlsConn.Handshake() error: %w", err)
					}

					return tlsConn, nil
				},
			},
		}
	}
	return http.DefaultClient
}

func (c *clientSelector) lookupIP(domain string) ([]string, error) {
	return chinadns.Client(c.dnsConfig).LookupIP(domain)
}

func (c *clientSelector) checkPortAvailable(ip string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

func getHostName(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "<nil>", false
	}
	return host, true
}

func (c *clientSelector) resolverCacheEnabled() bool {
	return c.resolverCache != nil
}

func (c *clientSelector) cacheResolverResult(domain string, ips []string) {
	if c.resolverCacheEnabled() {
		c.Lock()
		(*c.resolverCache)[domain] = ips[:]
		c.Unlock()
	}
}

func (c *clientSelector) getResolvedIPFromCache(domain string) ([]string, bool) {
	if c.resolverCacheEnabled() {
		c.RLock()
		defer c.RUnlock()
		ips, ok := (*c.resolverCache)[domain]
		if ok {
			return ips, ok
		}
	}
	return nil, false
}

func (c *clientSelector) removeUnavailableIP(ips []string, port string) []string {
	var result []string
	for _, ip := range ips {
		if c.checkPortAvailable(ip, port, time.Second) {
			result = append(result, ip)
		}
	}
	return result
}

func (c *clientSelector) lookupAvailableIP(host string, port string) ([]string, bool) {
	ips, ok := c.getResolvedIPFromCache(host)
	if ok {
		return ips, true
	}
	ips, err := c.lookupIP(host)
	if err != nil {
		return nil, false
	}
	result := c.removeUnavailableIP(ips, port)
	if len(result) == 0 {
		return nil, false
	}
	c.cacheResolverResult(host, result)
	return result, true
}

func (c *clientSelector) selectAvailableIPAddr(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "<nil>", false
	}
	ips, ok := c.lookupAvailableIP(host, port)
	if ok {
		randombyte := make([]byte, 1)
		io.ReadFull(rand.Reader, randombyte)
		index := int(randombyte[0]) % len(ips)
		return net.JoinHostPort(ips[index], port), true
	}
	return "<nil>", false
}

func Client(dnsconfig *chinadns.Config, config *Config) *http.Client {
	client := &clientSelector{}
	client.applyConfig(dnsconfig, config)
	return client.Client()
}
