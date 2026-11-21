package domainconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrUnsupported is a domain whose DNS provider does not offer Domain Connect
// for it, or does not offer the synchronous flow.
var ErrUnsupported = errors.New("domainconnect: the DNS provider of this domain does not offer Domain Connect")

// maxBody is the most bytes read from a provider's answer.
const maxBody = 1 << 20

// Resolver answers the TXT lookups of discovery.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Settings is what a DNS provider publishes about its Domain Connect support
// for a domain.
type Settings struct {
	ProviderID          string   `json:"providerId"`
	ProviderName        string   `json:"providerName"`
	ProviderDisplayName string   `json:"providerDisplayName"`
	URLSyncUX           string   `json:"urlSyncUX"`
	URLAsyncUX          string   `json:"urlAsyncUX"`
	URLAPI              string   `json:"urlAPI"`
	Width               int      `json:"width"`
	Height              int      `json:"height"`
	URLControlPanel     string   `json:"urlControlPanel"`
	NameServers         []string `json:"nameServers"`
}

// DisplayName is the name to show the customer.
func (s Settings) DisplayName() string {
	if s.ProviderDisplayName != "" {
		return s.ProviderDisplayName
	}
	return s.ProviderName
}

// Discovery is a domain's DNS provider, found.
type Discovery struct {
	// Domain is the zone Domain Connect works on: the root domain.
	Domain string
	// Host is what is left of the asked domain under Domain, empty at the
	// root.
	Host     string
	Settings Settings

	syncUX *url.URL
	api    *url.URL
}

// SyncHost is the host the customer's browser is sent to, to show before
// redirecting.
func (d Discovery) SyncHost() string {
	if d.syncUX == nil {
		return ""
	}
	return d.syncUX.Hostname()
}

// Client finds the DNS provider of a domain and asks it questions. The zero
// value works: it uses the system resolver and NewSafeClient.
type Client struct {
	// Resolver defaults to the system resolver.
	Resolver Resolver
	// HTTP defaults to NewSafeClient. A client of your own must refuse
	// internal addresses and redirects, because the addresses it is given come
	// from the customer's DNS.
	HTTP HTTPClient
}

func (c Client) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

func (c Client) http() HTTPClient {
	if c.HTTP != nil {
		return c.HTTP
	}
	return NewSafeClient(0)
}

// Discover finds the DNS provider of a domain.
//
// Discovery works on the root domain, which is not known without the public
// suffix list, so it asks for the _domainconnect TXT record from the whole name
// down to its last two labels and takes the first that names a provider that
// answers its settings for that name. A provider that is wrong for a name, or
// does not answer, is skipped, as the protocol asks. It answers ErrUnsupported
// when there is none, or when the provider has no synchronous flow.
func (c Client) Discover(ctx context.Context, domain string) (Discovery, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	labels := strings.Split(domain, ".")
	if domain == "" || len(labels) < 2 {
		return Discovery{}, fmt.Errorf("domainconnect: %q is not a domain", domain)
	}
	for i := 0; i+1 < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		texts, err := c.resolver().LookupTXT(ctx, "_domainconnect."+candidate)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			if ctx.Err() != nil {
				return Discovery{}, ctx.Err()
			}
			continue
		}
		for _, text := range texts {
			found, err := c.settings(ctx, candidate, text)
			if err != nil {
				continue
			}
			found.Host = strings.TrimSuffix(strings.TrimSuffix(domain, candidate), ".")
			if found.syncUX == nil {
				return Discovery{}, ErrUnsupported
			}
			return found, nil
		}
	}
	return Discovery{}, ErrUnsupported
}

// settings asks the provider a TXT record names for its settings on a zone.
func (c Client) settings(ctx context.Context, zone, prefix string) (Discovery, error) {
	base, err := parsePrefix(prefix)
	if err != nil {
		return Discovery{}, err
	}
	var s Settings
	status, err := c.getJSON(ctx, base.String()+"/v2/"+url.PathEscape(zone)+"/settings", &s)
	if err != nil {
		return Discovery{}, err
	}
	if status == http.StatusNotFound {
		return Discovery{}, ErrUnsupported
	}
	if s.ProviderID == "" || s.ProviderName == "" || s.URLAPI == "" {
		return Discovery{}, errors.New("domainconnect: the provider's settings are incomplete")
	}
	api, err := parsePrefix(s.URLAPI)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{Domain: zone, Settings: s, api: api}
	if s.URLSyncUX != "" {
		if d.syncUX, err = parsePrefix(s.URLSyncUX); err != nil {
			return Discovery{}, err
		}
	}
	return d, nil
}

// Supports asks the provider whether it has the service's template for the
// synchronous flow. A provider that has not onboarded the template answers
// false, and the customer is better served by the manual records.
func (c Client) Supports(ctx context.Context, d Discovery, providerID, serviceID string) (bool, error) {
	if d.api == nil {
		return false, ErrUnsupported
	}
	target := d.api.String() + "/v2/domainTemplates/providers/" + url.PathEscape(providerID) + "/services/" + url.PathEscape(serviceID)
	status, err := c.getJSON(ctx, target, nil)
	if err != nil {
		return false, err
	}
	switch {
	case status >= 200 && status < 300:
		return true, nil
	case status == http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("domainconnect: the provider answered %d when asked about the template", status)
}

// getJSON makes one GET and decodes a 2xx answer into into, when it is given.
// It answers the status of any answer it could read; a 404 is not an error.
func (c Client) getJSON(ctx context.Context, target string, into any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http().Do(request)
	if err != nil {
		return 0, fmt.Errorf("domainconnect: the provider did not answer: %w", errors.Unwrap(err))
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return response.StatusCode, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, nil
	}
	if into == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBody))
		return response.StatusCode, nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return response.StatusCode, fmt.Errorf("domainconnect: reading the provider's answer: %w", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return response.StatusCode, errors.New("domainconnect: the provider's answer is not the settings JSON")
	}
	return response.StatusCode, nil
}
