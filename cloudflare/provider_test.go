package cloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/cloudflare"
)

const (
	zoneID = "023e105f4ecef8ad9ca31a8372d0c353"
	secret = "tok_secret_value_123"
)

var zone = dns.Zone{ID: zoneID, Name: "example.com"}

// reply is a recorded answer: the status and the file under testdata.
type reply struct {
	status int
	file   string
}

// seen is one request the server received.
type seen struct {
	method, path string
	query        url.Values
	auth         string
	body         map[string]any
}

// server answers from recorded files and keeps what it was asked. No test in
// this package reaches the real API.
type server struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]reply
	asked  []seen
	*httptest.Server
}

func newServer(t *testing.T, routes map[string]reply) *server {
	t.Helper()
	s := &server{t: t, routes: routes}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := seen{method: r.Method, path: r.URL.Path, query: r.URL.Query(), auth: r.Header.Get("Authorization")}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &entry.body)
		}
		s.mu.Lock()
		s.asked = append(s.asked, entry)
		s.mu.Unlock()
		answer, ok := s.routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		raw, err := os.ReadFile(filepath.Join("testdata", answer.file))
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = w.Write(raw)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) provider(t *testing.T) *cloudflare.Provider {
	t.Helper()
	p, err := cloudflare.New(secret, cloudflare.WithBaseURL(s.URL), cloudflare.WithHTTPClient(cloudflare.NewHTTPClient(0)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindZoneAsksByNameFromTheLongestDown(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones": {200, "zones_none.json"}})
	p := s.provider(t)
	_, err := p.FindZone(context.Background(), "a.b.example.com")
	if !errors.Is(err, dns.ErrZoneNotFound) {
		t.Fatalf("err = %v, want ErrZoneNotFound", err)
	}
	var asked []string
	for _, r := range s.asked {
		asked = append(asked, r.query.Get("name"))
		if r.auth != "Bearer "+secret {
			t.Errorf("authorization = %q", r.auth)
		}
	}
	if strings.Join(asked, ",") != "a.b.example.com,b.example.com,example.com" {
		t.Errorf("asked for %v; the bare TLD must never be asked", asked)
	}
}

func TestFindZoneAnswersTheZoneTheCredentialSees(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones": {200, "zones.json"}})
	got, err := dns.FindZone(context.Background(), s.provider(t), "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != zoneID || got.Name != "mail.example.com" && got.Name != "example.com" {
		t.Errorf("zone = %+v", got)
	}
}

func TestRecordsAreAskedByExactNameAndReadAsTheyComeBack(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones/" + zoneID + "/dns_records": {200, "records_apex_mx.json"}})
	records, err := s.provider(t).Records(context.Background(), zone, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.asked[0].query.Get("name.exact"); got != "example.com" {
		t.Errorf("name.exact = %q", got)
	}
	if len(records) != 2 || records[0].Type != dns.TypeMX || records[0].Priority != 92 || records[0].Content != "route3.mx.cloudflare.net" {
		t.Errorf("records = %+v", records)
	}
	if records[0].TTL != 0 {
		t.Errorf("ttl = %d, Cloudflare's automatic 1 is zero here", records[0].TTL)
	}
}

func TestQuotedAndUnquotedTXTRecordsBothCompareEqual(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones/" + zoneID + "/dns_records": {200, "records_txt_mixed.json"}})
	records, err := s.provider(t).Records(context.Background(), zone)
	if err != nil {
		t.Fatal(err)
	}
	long, _ := os.ReadFile("testdata/dkim_long.txt")
	var quoted, bare dns.Record
	for _, r := range records {
		switch r.Name {
		case "cf2024-1._domainkey.example.com":
			quoted = r
		case "meeng._domainkey.example.com":
			bare = r
		}
	}
	if dns.NormalizeContent(dns.TypeTXT, quoted.Content) != string(long) {
		t.Error("the quoted two-chunk key does not join back to the whole")
	}
	if !strings.HasPrefix(bare.Content, "p=") {
		t.Errorf("bare = %q", bare.Content)
	}
	if len(s.asked) != 1 || s.asked[0].query.Get("name.exact") != "" {
		t.Error("listing the whole zone must not filter by name")
	}
}

func TestCreateSendsTheRecordAndNothingElse(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"POST /zones/" + zoneID + "/dns_records": {200, "record_created.json"}})
	created, err := s.provider(t).Create(context.Background(), zone, dns.Record{
		Type: dns.TypeMX, Name: "mail.example.com", Content: "mx.example.net", Priority: 10, Comment: "Created by Meeng.dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "cccccccccccccccccccccccccccccc01" {
		t.Errorf("id = %q", created.ID)
	}
	body := s.asked[0].body
	want := map[string]any{"type": "MX", "name": "mail.example.com", "content": "mx.example.net", "priority": float64(10), "ttl": float64(1), "comment": "Created by Meeng.dev"}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, body[k], v)
		}
	}
	if len(body) != len(want) {
		t.Errorf("body = %v carries more than was asked", body)
	}
}

func TestALongTXTValueIsSentAsQuotedChunks(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"POST /zones/" + zoneID + "/dns_records": {200, "record_created.json"}})
	long, _ := os.ReadFile("testdata/dkim_long.txt")
	if _, err := s.provider(t).Create(context.Background(), zone, dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: string(long)}); err != nil {
		t.Fatal(err)
	}
	sent, _ := s.asked[0].body["content"].(string)
	if !strings.HasPrefix(sent, `"`) || dns.NormalizeContent(dns.TypeTXT, sent) != string(long) {
		t.Errorf("content = %.40q..., want quoted chunks that join back to the key", sent)
	}
}

func TestUpdateOverwritesTheRecordWithThatID(t *testing.T) {
	t.Parallel()
	path := "/zones/" + zoneID + "/dns_records/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb4"
	s := newServer(t, map[string]reply{"PUT " + path: {200, "record_created.json"}})
	_, err := s.provider(t).Update(context.Background(), zone, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb4",
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=NEW"})
	if err != nil {
		t.Fatal(err)
	}
	if s.asked[0].method != http.MethodPut || s.asked[0].path != path {
		t.Errorf("request = %s %s", s.asked[0].method, s.asked[0].path)
	}
	if _, err := s.provider(t).Update(context.Background(), zone, "", dns.Record{}); err == nil {
		t.Error("an update with no ID must be refused before any call")
	}
}

func TestTheErrorsMeanWhatCloudflareSaid(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		route  reply
		method string
		want   error
	}{
		"invalid token": {reply{403, "error_invalid_token.json"}, "GET", dns.ErrUnauthorized},
		"unauthorized":  {reply{401, "error_invalid_token.json"}, "GET", dns.ErrUnauthorized},
		"missing scope": {reply{403, "error_forbidden.json"}, "GET", dns.ErrForbidden},
		"rate limited":  {reply{429, "error_rate.json"}, "GET", dns.ErrRateLimited},
		"duplicate":     {reply{400, "error_duplicate.json"}, "POST", dns.ErrRecordExists},
	} {
		path := "/zones/" + zoneID + "/dns_records"
		s := newServer(t, map[string]reply{c.method + " " + path: c.route})
		p := s.provider(t)
		var err error
		if c.method == "POST" {
			_, err = p.Create(context.Background(), zone, dns.Record{Type: dns.TypeTXT, Name: "a.example.com", Content: "x"})
		} else {
			_, err = p.Records(context.Background(), zone, "a.example.com")
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
		var pe *dns.ProviderError
		if !errors.As(err, &pe) || pe.Status != c.route.status {
			t.Errorf("%s: no ProviderError with status %d in %v", name, c.route.status, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error carries the token", name)
		}
	}
}

func TestAnErrorFromTheTransportNeverCarriesTheToken(t *testing.T) {
	t.Parallel()
	p, err := cloudflare.New(secret, cloudflare.WithBaseURL("http://127.0.0.1:1/"+secret), cloudflare.WithHTTPClient(cloudflare.NewHTTPClient(0)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Zones(context.Background())
	if err == nil {
		t.Fatal("want an error from a closed port")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error carries the token: %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	t.Parallel()
	hits := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "" {
			t.Error("the credential followed a redirect")
		}
	}))
	defer elsewhere.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirect.Close()
	p, _ := cloudflare.New(secret, cloudflare.WithBaseURL(redirect.URL))
	if _, err := p.Zones(context.Background()); err == nil {
		t.Error("a redirect is not an answer")
	}
	if hits != 0 {
		t.Errorf("the redirect target was reached %d times", hits)
	}
}

func TestATokenWithSpacesOrNothingIsRefused(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"", "   ", "abc def", "abc\ndef"} {
		if _, err := cloudflare.New(token); err == nil {
			t.Errorf("token %q was accepted", token)
		}
	}
}

func TestAPlanThroughTheCloudflareProviderLeavesTheApexAlone(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones/" + zoneID + "/dns_records": {200, "records_apex_mx.json"}})
	plan, err := dns.NewPlan(context.Background(), s.provider(t), zone,
		dns.Want{Type: dns.TypeMX, Name: "@", Content: "mx.example.net", Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Items[0].Action != dns.ActionConflict || plan.Items[0].Code != dns.ConflictApex {
		t.Errorf("item = %+v, want an apex conflict with Cloudflare's own routing MX", plan.Items[0])
	}
	for _, r := range s.asked {
		if r.method != http.MethodGet {
			t.Errorf("planning made a %s request", r.method)
		}
	}
}

func TestDeleteRemovesTheRecordWithThatID(t *testing.T) {
	t.Parallel()
	id := "dddddddddddddddddddddddddddddd01"
	path := "/zones/" + zoneID + "/dns_records/" + id
	s := newServer(t, map[string]reply{"DELETE " + path: {200, "delete_ok.json"}})
	if err := s.provider(t).Delete(context.Background(), zone, id); err != nil {
		t.Fatal(err)
	}
	if s.asked[0].method != http.MethodDelete || s.asked[0].path != path || s.asked[0].auth != "Bearer "+secret {
		t.Errorf("request = %+v", s.asked[0])
	}
	if err := s.provider(t).Delete(context.Background(), zone, ""); err == nil {
		t.Error("a removal with no ID must be refused before any call")
	}
	denied := newServer(t, map[string]reply{"DELETE " + path: {403, "error_forbidden.json"}})
	if err := denied.provider(t).Delete(context.Background(), zone, id); !errors.Is(err, dns.ErrForbidden) {
		t.Errorf("err = %v, want ErrForbidden", err)
	}
}

func TestRecordsUnderAsksForTheSuffixAndKeepsOnlyTheLabelsUnderIt(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]reply{"GET /zones/" + zoneID + "/dns_records": {200, "records_under.json"}})
	records, err := s.provider(t).RecordsUnder(context.Background(), zone, "updates.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.asked[0].query.Get("name.endswith"); got != "updates.example.com" {
		t.Errorf("name.endswith = %q", got)
	}
	var names []string
	for _, r := range records {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "send.updates.example.com,resend._domainkey.updates.example.com,updates.example.com" {
		t.Errorf("names = %v; not-updates.example.com ends in the suffix without being under it", names)
	}
}

func TestAReplacementThroughTheCloudflareProviderRemovesThenCreates(t *testing.T) {
	t.Parallel()
	id := "dddddddddddddddddddddddddddddd01"
	base := "/zones/" + zoneID + "/dns_records"
	s := newServer(t, map[string]reply{
		"GET " + base:               {200, "records_under.json"},
		"DELETE " + base + "/" + id: {200, "delete_ok.json"},
		"POST " + base:              {200, "record_created.json"},
	})
	p := s.provider(t)
	plan, err := dns.NewPlan(context.Background(), p, zone,
		dns.Want{Type: dns.TypeCNAME, Name: "send.updates", Content: "return.example.net", Takeover: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Items[0].Action != dns.ActionReplace {
		t.Fatalf("action = %s, want replace", plan.Items[0].Action)
	}
	report, err := dns.Apply(context.Background(), p, plan)
	if err != nil || report.Count(dns.OutcomeReplaced) != 1 {
		t.Fatalf("report = %+v, err = %v", report.Results, err)
	}
	var order []string
	for _, r := range s.asked {
		if r.method != http.MethodGet {
			order = append(order, r.method)
		}
	}
	if strings.Join(order, ",") != "DELETE,POST" {
		t.Errorf("writes = %v, want the removal before the creation", order)
	}
}
