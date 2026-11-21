package domainconnect_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hyz-is/arandu-dns/domainconnect"
)

// resolver answers TXT lookups from a map; a name that is not in it does not
// exist.
type resolver map[string][]string

func (r resolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if texts, ok := r[name]; ok {
		return texts, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// routes is a recorded provider: it answers by "host/path" with a status and a
// file under testdata, and keeps every URL it was asked.
type routes struct {
	t      testing.TB
	mu     sync.Mutex
	answer map[string]answer
	asked  []string
}

type answer struct {
	status int
	file   string
}

func (r *routes) Do(request *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.asked = append(r.asked, request.URL.Host+request.URL.Path)
	r.mu.Unlock()
	hit, ok := r.answer[request.URL.Host+request.URL.Path]
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	}
	body := ""
	if hit.file != "" {
		raw, err := os.ReadFile(filepath.Join("testdata", hit.file))
		if err != nil {
			r.t.Fatal(err)
		}
		body = string(raw)
	}
	return &http.Response{StatusCode: hit.status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

// cloudflare is what a domain on Cloudflare returns, recorded from the real
// service: the TXT value has a path, the settings come from under it.
func cloudflare(t testing.TB) (domainconnect.Client, *routes) {
	t.Helper()
	r := &routes{t: t, answer: map[string]answer{
		"api.cloudflare.com/client/v4/dns/domainconnect/v2/example.com/settings":                                   {200, "settings_cloudflare.json"},
		"api.cloudflare.com/client/v4/dns/domainconnect/v2/domainTemplates/providers/example.com/services/sending": {200, ""},
	}}
	dns := resolver{"_domainconnect.example.com": {"api.cloudflare.com/client/v4/dns/domainconnect"}}
	return domainconnect.Client{Resolver: dns, HTTP: r}, r
}

func TestDiscoverReadsTheProviderOfARootDomain(t *testing.T) {
	t.Parallel()
	client, _ := cloudflare(t)
	d, err := client.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Domain != "example.com" || d.Host != "" || d.Settings.ProviderID != "cloudflare.com" || d.Settings.DisplayName() != "Cloudflare" {
		t.Errorf("discovery = %+v", d)
	}
	if d.SyncHost() != "dash.cloudflare.com" {
		t.Errorf("sync host = %q", d.SyncHost())
	}
}

func TestDiscoverSplitsASubdomainFromItsRoot(t *testing.T) {
	t.Parallel()
	client, r := cloudflare(t)
	d, err := client.Discover(context.Background(), "Send.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if d.Domain != "example.com" || d.Host != "send" {
		t.Errorf("domain = %q host = %q, want example.com and send", d.Domain, d.Host)
	}
	for _, url := range r.asked {
		if strings.Contains(url, "send.example.com") {
			t.Errorf("asked the provider about the subdomain: %s", url)
		}
	}
}

func TestAProviderThatDoesNotKnowTheSubdomainIsSkippedForTheRoot(t *testing.T) {
	t.Parallel()
	// Both names resolve to the provider, as with a wildcard, but the provider
	// has the zone only at the root: it answers 404 for the subdomain.
	r := &routes{t: t, answer: map[string]answer{
		"api.cloudflare.com/client/v4/dns/domainconnect/v2/example.com/settings": {200, "settings_cloudflare.json"},
	}}
	txt := "api.cloudflare.com/client/v4/dns/domainconnect"
	client := domainconnect.Client{Resolver: resolver{"_domainconnect.a.b.example.com": {txt}, "_domainconnect.b.example.com": {txt}, "_domainconnect.example.com": {txt}}, HTTP: r}
	d, err := client.Discover(context.Background(), "a.b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Domain != "example.com" || d.Host != "a.b" {
		t.Errorf("domain = %q host = %q", d.Domain, d.Host)
	}
}

func TestADomainWithoutTheRecordIsUnsupported(t *testing.T) {
	t.Parallel()
	client := domainconnect.Client{Resolver: resolver{}, HTTP: &routes{t: t}}
	if _, err := client.Discover(context.Background(), "example.com"); !errors.Is(err, domainconnect.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
	if _, err := client.Discover(context.Background(), "com"); err == nil {
		t.Error("a single label is not a domain")
	}
}

func TestAProviderWithoutTheSynchronousFlowIsUnsupported(t *testing.T) {
	t.Parallel()
	r := &routes{t: t, answer: map[string]answer{"asyncprovider.example/v2/example.com/settings": {200, "settings_no_sync.json"}}}
	client := domainconnect.Client{Resolver: resolver{"_domainconnect.example.com": {"asyncprovider.example"}}, HTTP: r}
	if _, err := client.Discover(context.Background(), "example.com"); !errors.Is(err, domainconnect.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestAnAddressInTheCustomersDNSThatIsNotAPublicHTTPSNameIsNeverCalled(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"http://provider.example", "169.254.169.254", "https://127.0.0.1", "localhost", "https://user:pw@provider.example",
		"provider.example:8080", "https://[::1]", "intranet", "https://provider.example?x=1", "host.internal", "printer.local",
	} {
		r := &routes{t: t}
		client := domainconnect.Client{Resolver: resolver{"_domainconnect.example.com": {value}}, HTTP: r}
		if _, err := client.Discover(context.Background(), "example.com"); !errors.Is(err, domainconnect.ErrUnsupported) {
			t.Errorf("%q: err = %v, want ErrUnsupported", value, err)
		}
		if len(r.asked) != 0 {
			t.Errorf("%q: the address was called: %v", value, r.asked)
		}
	}
}

func TestSettingsWhoseAPIPointsInsideAreRefused(t *testing.T) {
	t.Parallel()
	r := &routes{t: t, answer: map[string]answer{"provider.example/v2/example.com/settings": {200, "settings_internal.json"}}}
	client := domainconnect.Client{Resolver: resolver{"_domainconnect.example.com": {"provider.example"}}, HTTP: r}
	if _, err := client.Discover(context.Background(), "example.com"); !errors.Is(err, domainconnect.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestSupportsAsksTheProviderAboutTheTemplate(t *testing.T) {
	t.Parallel()
	client, r := cloudflare(t)
	d, err := client.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := client.Supports(context.Background(), d, "example.com", "sending")
	if err != nil || !ok {
		t.Errorf("Supports = %v, %v; want true", ok, err)
	}
	ok, err = client.Supports(context.Background(), d, "example.com", "unknown")
	if err != nil || ok {
		t.Errorf("Supports(unknown) = %v, %v; want false", ok, err)
	}
	last := r.asked[len(r.asked)-1]
	if !strings.HasSuffix(last, "/v2/domainTemplates/providers/example.com/services/unknown") {
		t.Errorf("asked %s", last)
	}
}

func TestTheDefaultClientRefusesAnInternalAddress(t *testing.T) {
	t.Parallel()
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	_, err := domainconnect.NewSafeClient(0).Get(srv.URL)
	if err == nil || !errors.Is(err, domainconnect.ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits != 0 {
		t.Error("the loopback server was reached")
	}
}

func TestTheDefaultClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	client := domainconnect.NewSafeClient(0)
	if client.CheckRedirect == nil {
		t.Fatal("the client follows redirects")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v", err)
	}
}
