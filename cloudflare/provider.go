package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	dns "github.com/hyz-is/arandu-dns"
)

// DefaultBaseURL is the Cloudflare API.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// The most pages of zones or records one call walks, so a credential that sees
// a very large account cannot make one request run without end.
const maxPages = 40

// maxBody is the most bytes read from one answer.
const maxBody = 8 << 20

// HTTPClient is what the provider calls the API with.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// NewHTTPClient is the client the provider uses when none is given: a timeout,
// and no redirects, because a redirect would carry the credential to wherever
// the answer points.
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Provider is the Cloudflare DNS provider for one credential.
type Provider struct {
	token   string
	baseURL string
	client  HTTPClient
}

var (
	_ dns.Provider   = (*Provider)(nil)
	_ dns.ZoneFinder = (*Provider)(nil)
	_ dns.Remover    = (*Provider)(nil)
	_ dns.Lister     = (*Provider)(nil)
)

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient sets the client the provider calls with. It must not follow
// redirects.
func WithHTTPClient(client HTTPClient) Option { return func(p *Provider) { p.client = client } }

// WithBaseURL points the provider at another API root, such as a test server.
func WithBaseURL(base string) Option {
	return func(p *Provider) { p.baseURL = strings.TrimSuffix(base, "/") }
}

// New returns the provider for a bearer token: an API token or an OAuth access
// token.
func New(token string, options ...Option) (*Provider, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("cloudflare: the token is empty")
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("cloudflare: the token has spaces in it")
	}
	p := &Provider{token: token, baseURL: DefaultBaseURL}
	for _, option := range options {
		option(p)
	}
	if p.client == nil {
		p.client = NewHTTPClient(0)
	}
	return p, nil
}

// Name implements dns.Provider.
func (p *Provider) Name() string { return "cloudflare" }

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type apiZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
	Proxied  *bool  `json:"proxied,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// Zones implements dns.Provider.
func (p *Provider) Zones(ctx context.Context) ([]dns.Zone, error) {
	var out []dns.Zone
	for page := 1; page <= maxPages; page++ {
		var zones []apiZone
		info, err := p.do(ctx, http.MethodGet, "/zones", url.Values{"per_page": {"50"}, "page": {strconv.Itoa(page)}}, nil, &zones)
		if err != nil {
			return nil, err
		}
		for _, z := range zones {
			out = append(out, dns.Zone{ID: z.ID, Name: strings.ToLower(z.Name)})
		}
		if page >= info.TotalPages {
			break
		}
	}
	return out, nil
}

// FindZone implements dns.ZoneFinder. It asks for the zone by name, from the
// whole domain down to its last two labels, and answers the first the
// credential can see.
func (p *Provider) FindZone(ctx context.Context, domain string) (dns.Zone, error) {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")), ".")
	for i := 0; i+1 < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		var zones []apiZone
		if _, err := p.do(ctx, http.MethodGet, "/zones", url.Values{"name": {name}}, nil, &zones); err != nil {
			return dns.Zone{}, err
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, name) {
				return dns.Zone{ID: z.ID, Name: name}, nil
			}
		}
	}
	return dns.Zone{}, dns.ErrZoneNotFound
}

// Records implements dns.Provider. With names it asks for each name exactly;
// without, for the whole zone.
func (p *Provider) Records(ctx context.Context, zone dns.Zone, names ...string) ([]dns.Record, error) {
	if len(names) == 0 {
		return p.listRecords(ctx, zone, nil)
	}
	var out []dns.Record
	for _, name := range names {
		records, err := p.listRecords(ctx, zone, url.Values{"name.exact": {name}})
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

func (p *Provider) listRecords(ctx context.Context, zone dns.Zone, filter url.Values) ([]dns.Record, error) {
	var out []dns.Record
	for page := 1; page <= maxPages; page++ {
		query := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		for k, v := range filter {
			query[k] = v
		}
		var records []apiRecord
		info, err := p.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", query, nil, &records)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			out = append(out, fromAPI(r))
		}
		if page >= info.TotalPages {
			break
		}
	}
	return out, nil
}

// Create implements dns.Provider.
func (p *Provider) Create(ctx context.Context, zone dns.Zone, record dns.Record) (dns.Record, error) {
	var created apiRecord
	_, err := p.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", nil, toAPI(record), &created)
	if err != nil {
		return dns.Record{}, err
	}
	return fromAPI(created), nil
}

// Update implements dns.Provider. It overwrites the record with that ID.
func (p *Provider) Update(ctx context.Context, zone dns.Zone, id string, record dns.Record) (dns.Record, error) {
	if id == "" {
		return dns.Record{}, errors.New("cloudflare: an update needs the record's ID")
	}
	var updated apiRecord
	_, err := p.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(id), nil, toAPI(record), &updated)
	if err != nil {
		return dns.Record{}, err
	}
	return fromAPI(updated), nil
}

// Delete implements dns.Remover. It removes the record with that ID.
func (p *Provider) Delete(ctx context.Context, zone dns.Zone, id string) error {
	if id == "" {
		return errors.New("cloudflare: a removal needs the record's ID")
	}
	_, err := p.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(id), nil, nil, nil)
	return err
}

// RecordsUnder implements dns.Lister. It asks for the names that end in name
// and keeps the ones that are name or a label sequence under it.
func (p *Provider) RecordsUnder(ctx context.Context, zone dns.Zone, name string) ([]dns.Record, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	found, err := p.listRecords(ctx, zone, url.Values{"name.endswith": {name}})
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, r := range found {
		if r.Name == name || strings.HasSuffix(r.Name, "."+name) {
			out = append(out, r)
		}
	}
	return out, nil
}

func fromAPI(r apiRecord) dns.Record {
	record := dns.Record{
		ID: r.ID, Type: dns.RecordType(strings.ToUpper(r.Type)), Name: strings.ToLower(r.Name),
		Content: r.Content, Comment: r.Comment,
	}
	if r.TTL > 1 {
		record.TTL = r.TTL
	}
	if r.Priority != nil {
		record.Priority = *r.Priority
	}
	return record
}

func toAPI(r dns.Record) apiRecord {
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 1 // automatic
	}
	out := apiRecord{Type: string(r.Type), Name: r.Name, Content: r.Content, TTL: ttl, Comment: r.Comment}
	switch r.Type {
	case dns.TypeMX:
		priority := r.Priority
		out.Priority = &priority
	case dns.TypeTXT:
		out.Content = chunkTXT(r.Content)
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME:
		proxied := false
		out.Proxied = &proxied
	}
	return out
}

// chunkTXT writes a TXT value longer than 255 bytes as the quoted chunks the
// API documents, and leaves a shorter one as it is.
func chunkTXT(content string) string {
	if len(content) <= 255 {
		return content
	}
	var out strings.Builder
	for len(content) > 0 {
		n := min(255, len(content))
		if out.Len() > 0 {
			out.WriteByte(' ')
		}
		out.WriteByte('"')
		out.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(content[:n]))
		out.WriteByte('"')
		content = content[n:]
	}
	return out.String()
}

type pageInfo struct{ TotalPages int }

// do makes one call and decodes the result. The credential goes in the
// Authorization header and nowhere else, and no error text includes it.
func (p *Provider) do(ctx context.Context, method, path string, query url.Values, body any, into any) (pageInfo, error) {
	target := p.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return pageInfo{}, fmt.Errorf("cloudflare: encoding the request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return pageInfo{}, fmt.Errorf("cloudflare: building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := p.client.Do(request)
	if err != nil {
		// The client's error repeats the URL, which holds no secret, and not the
		// headers.
		return pageInfo{}, &dns.ProviderError{Provider: "cloudflare", Messages: []string{"the request did not complete: " + sanitize(err.Error(), p.token)}}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return pageInfo{}, &dns.ProviderError{Provider: "cloudflare", Status: response.StatusCode, Messages: []string{"the answer could not be read"}}
	}

	var reply envelope
	decodeErr := json.Unmarshal(raw, &reply)
	if response.StatusCode >= 300 || (decodeErr == nil && !reply.Success) {
		return pageInfo{}, apiError(response.StatusCode, reply, decodeErr)
	}
	if decodeErr != nil {
		return pageInfo{}, &dns.ProviderError{Provider: "cloudflare", Status: response.StatusCode, Messages: []string{"the answer is not JSON"}}
	}
	if into != nil && len(reply.Result) > 0 && string(reply.Result) != "null" {
		if err := json.Unmarshal(reply.Result, into); err != nil {
			return pageInfo{}, &dns.ProviderError{Provider: "cloudflare", Status: response.StatusCode, Messages: []string{"the result has an unexpected shape"}}
		}
	}
	return pageInfo{TotalPages: reply.ResultInfo.TotalPages}, nil
}

// apiError turns a failed answer into a ProviderError that carries the sentinel
// its status and codes mean.
func apiError(status int, reply envelope, decodeErr error) error {
	e := &dns.ProviderError{Provider: "cloudflare", Status: status}
	codes := map[int]bool{}
	for _, m := range reply.Errors {
		codes[m.Code] = true
		if m.Message != "" {
			e.Messages = append(e.Messages, m.Message)
		}
	}
	switch {
	case status == http.StatusUnauthorized, codes[9109], codes[6003], codes[6111]:
		e.Err = dns.ErrUnauthorized
	case status == http.StatusForbidden:
		e.Err = dns.ErrForbidden
	case status == http.StatusTooManyRequests:
		e.Err = dns.ErrRateLimited
	case codes[81057], codes[81058]:
		e.Err = dns.ErrRecordExists
	}
	if len(e.Messages) == 0 && decodeErr != nil {
		e.Messages = []string{"no error message came with the answer"}
	}
	return e
}

func sanitize(text, token string) string {
	if token != "" {
		text = strings.ReplaceAll(text, token, "[token]")
	}
	return text
}
