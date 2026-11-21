package cloudflare_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/cloudflare"
)

func oauthClient() cloudflare.OAuth {
	return cloudflare.OAuth{ClientID: "client-id", ClientSecret: "client-secret", RedirectURI: "https://meeng.example/callback"}
}

func TestTheAuthorizationURLCarriesPKCEAndTheScopesDNSNeeds(t *testing.T) {
	t.Parallel()
	pkce, err := cloudflare.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := oauthClient().AuthorizationURL("state-1", pkce)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host != "dash.cloudflare.com" || u.Path != "/oauth2/auth" {
		t.Fatalf("url = %s, %v", raw, err)
	}
	q := u.Query()
	for k, v := range map[string]string{
		"response_type": "code", "client_id": "client-id", "redirect_uri": "https://meeng.example/callback",
		"scope": "zone.read dns.write", "state": "state-1", "code_challenge": pkce.Challenge, "code_challenge_method": "S256",
	} {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if strings.Contains(raw, "client-secret") || strings.Contains(raw, pkce.Verifier) {
		t.Error("the URL carries the secret or the verifier")
	}
	if strings.Contains(q.Get("scope"), "offline") {
		t.Error("a refresh token must never be asked for")
	}
}

func TestEveryPKCEPairIsFreshAndTheChallengeIsTheHash(t *testing.T) {
	t.Parallel()
	a, _ := cloudflare.NewPKCE()
	b, _ := cloudflare.NewPKCE()
	if a.Verifier == b.Verifier || len(a.Verifier) < 43 {
		t.Errorf("verifiers %q and %q must differ and be at least 43 characters", a.Verifier, b.Verifier)
	}
}

func TestExchangeTradesTheCodeAndAuthenticatesTheClient(t *testing.T) {
	t.Parallel()
	var form url.Values
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(raw))
		user, pass, _ = r.BasicAuth()
		body, _ := os.ReadFile("testdata/oauth_token.json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	o := oauthClient()
	o.TokenEndpoint = srv.URL
	token, err := o.Exchange(context.Background(), "the-code", cloudflare.PKCE{Verifier: "the-verifier", Challenge: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "cfat_example_access_token" || token.Scope != "zone.read dns.write" || token.ExpiresIn != 3599 {
		t.Errorf("token = %+v", token)
	}
	if user != "client-id" || pass != "client-secret" {
		t.Errorf("basic auth = %q/%q", user, pass)
	}
	for k, v := range map[string]string{"grant_type": "authorization_code", "code": "the-code", "code_verifier": "the-verifier", "redirect_uri": "https://meeng.example/callback"} {
		if form.Get(k) != v {
			t.Errorf("form %s = %q", k, form.Get(k))
		}
	}
}

func TestAnExchangeRefusedIsAnUnauthorizedErrorWithoutTheSecret(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/oauth_error.json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	o := oauthClient()
	o.TokenEndpoint = srv.URL
	_, err := o.Exchange(context.Background(), "used-code", cloudflare.PKCE{Verifier: "v"})
	if !errors.Is(err, dns.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "client-secret") || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("err = %v", err)
	}
}

func TestRevokeSendsTheToken(t *testing.T) {
	t.Parallel()
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(raw))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	o := oauthClient()
	o.RevokeEndpoint = srv.URL
	if err := o.Revoke(context.Background(), "cfat_example_access_token"); err != nil {
		t.Fatal(err)
	}
	if got.Get("token") != "cfat_example_access_token" {
		t.Errorf("form = %v", got)
	}
	if err := o.Revoke(context.Background(), ""); err != nil {
		t.Errorf("revoking nothing is not an error: %v", err)
	}
}

func TestAnIncompleteClientIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := (cloudflare.OAuth{}).AuthorizationURL("s", cloudflare.PKCE{Challenge: "c"}); err == nil {
		t.Error("an empty client built an authorization URL")
	}
	if _, err := oauthClient().AuthorizationURL("", cloudflare.PKCE{Challenge: "c"}); err == nil {
		t.Error("a missing state was accepted")
	}
}

func BenchmarkChunkedCreate(b *testing.B) {
	b.ReportAllocs()
	long, _ := os.ReadFile("testdata/dkim_long.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/record_created.json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	p, _ := cloudflare.New("token", cloudflare.WithBaseURL(srv.URL))
	for b.Loop() {
		if _, err := p.Create(b.Context(), zone, dns.Record{Type: dns.TypeTXT, Name: "a.example.com", Content: string(long)}); err != nil {
			b.Fatal(err)
		}
	}
}
