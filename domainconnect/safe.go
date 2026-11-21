package domainconnect

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress is a connection refused because it would reach a private,
// loopback, link-local or otherwise internal address.
var ErrBlockedAddress = errors.New("domainconnect: refused to connect to an internal address")

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// internal reports whether an address is one a public service must not be made
// to call: this machine, its network, or a link-local or metadata address.
func internal(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() ||
		addr.IsUnspecified() || carrierGradeNAT.Contains(addr)
}

// refuseInternal is a net.Dialer Control: it runs with the address the name
// resolved to, at the moment of connecting, so a name that points at an
// internal address is refused whatever it is called.
func refuseInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddress
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || internal(addr) {
		return ErrBlockedAddress
	}
	return nil
}

// HTTPClient is what Client calls providers with.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// NewSafeClient is the default HTTP client: a timeout, no redirects, no proxy
// and no connection to an internal address.
func NewSafeClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: refuseInternal}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// parsePrefix reads a URL prefix a provider publishes, such as
// "domainconnect.example" or "https://api.example/dc", and answers it as an
// https URL without a trailing slash. A provider that publishes an address a
// service should not call is refused: another scheme, credentials in the
// address, a port, an IP literal or a single-label host.
func parsePrefix(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("domainconnect: the provider published an empty address")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, errors.New("domainconnect: the provider published an address that is not a URL")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("domainconnect: the provider's address is not https")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("domainconnect: the provider's address carries credentials, a query or a fragment")
	case u.Port() != "":
		return nil, errors.New("domainconnect: the provider's address names a port")
	}
	host := strings.ToLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		_ = addr
		return nil, errors.New("domainconnect: the provider's address is an IP literal, not a name")
	}
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || host == "localhost" {
		return nil, errors.New("domainconnect: the provider's address is not a public name")
	}
	u.Host = host
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}
