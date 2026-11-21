package cloudflare

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	dns "github.com/hyz-is/arandu-dns"
)

// The endpoints of Cloudflare's OAuth 2.0 server.
const (
	AuthorizeURL = "https://dash.cloudflare.com/oauth2/auth"
	TokenURL     = "https://dash.cloudflare.com/oauth2/token"
	RevokeURL    = "https://dash.cloudflare.com/oauth2/revoke"
)

// DefaultScopes are what editing a zone's DNS needs: reading the zone list to
// find the zone, and writing its records.
var DefaultScopes = []string{"zone.read", "dns.write"}

// OAuth is an application's OAuth 2.0 client at Cloudflare: the authorization
// code flow, with PKCE, for a server-side application with a client secret.
//
// It never asks for a refresh token. The access token it returns is meant to be
// used within one request flow and revoked afterwards with Revoke.
type OAuth struct {
	ClientID     string
	ClientSecret string
	// RedirectURI is the address of the application's callback, exactly as it
	// is registered with the client.
	RedirectURI string
	// Scopes defaults to DefaultScopes.
	Scopes []string

	// HTTP defaults to NewHTTPClient.
	HTTP HTTPClient
	// AuthorizeEndpoint, TokenEndpoint and RevokeEndpoint default to the
	// Cloudflare ones. They exist for tests.
	AuthorizeEndpoint, TokenEndpoint, RevokeEndpoint string
}

// Token is what the token endpoint answers.
type Token struct {
	AccessToken string
	// ExpiresIn is the lifetime in seconds, when the server says.
	ExpiresIn int
	Scope     string
}

// Validate reports what the client cannot be used without.
func (o OAuth) Validate() error {
	switch {
	case o.ClientID == "":
		return errors.New("cloudflare: the OAuth client has no ID")
	case o.ClientSecret == "":
		return errors.New("cloudflare: the OAuth client has no secret")
	case o.RedirectURI == "":
		return errors.New("cloudflare: the OAuth client has no redirect URI")
	}
	return nil
}

func (o OAuth) scopes() string {
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	return strings.Join(scopes, " ")
}

func (o OAuth) client() HTTPClient {
	if o.HTTP != nil {
		return o.HTTP
	}
	return NewHTTPClient(0)
}

func pick(custom, fallback string) string {
	if custom != "" {
		return custom
	}
	return fallback
}

// PKCE is a code verifier and its challenge.
type PKCE struct {
	// Verifier is kept by the application until the callback.
	Verifier string
	// Challenge is sent to Cloudflare with the authorization request.
	Challenge string
}

// NewPKCE makes a fresh pair. Use one per authorization.
func NewPKCE() (PKCE, error) {
	verifier, err := Random(32)
	if err != nil {
		return PKCE{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// Random answers n random bytes as URL-safe text, for a state or a verifier.
func Random(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cloudflare: no randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// AuthorizationURL is where to send the customer's browser. The state is the
// application's anti-forgery value, returned on the callback.
func (o OAuth) AuthorizationURL(state string, pkce PKCE) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	if state == "" || pkce.Challenge == "" {
		return "", errors.New("cloudflare: authorization needs a state and a PKCE challenge")
	}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {o.RedirectURI},
		"scope":                 {o.scopes()},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
	}
	return pick(o.AuthorizeEndpoint, AuthorizeURL) + "?" + query.Encode(), nil
}

// Exchange trades the code of the callback for an access token.
func (o OAuth) Exchange(ctx context.Context, code string, pkce PKCE) (Token, error) {
	if err := o.Validate(); err != nil {
		return Token{}, err
	}
	if code == "" || pkce.Verifier == "" {
		return Token{}, errors.New("cloudflare: the exchange needs the code and the PKCE verifier")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {o.RedirectURI},
		"code_verifier": {pkce.Verifier},
	}
	body, status, err := o.post(ctx, pick(o.TokenEndpoint, TokenURL), form)
	if err != nil {
		return Token{}, err
	}
	var reply struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return Token{}, &dns.ProviderError{Provider: "cloudflare", Status: status, Messages: []string{"the token endpoint did not answer JSON"}}
	}
	if status >= 300 || reply.AccessToken == "" {
		message := reply.Error
		if reply.Description != "" {
			message += ": " + reply.Description
		}
		if message == "" {
			message = "no token was issued"
		}
		return Token{}, &dns.ProviderError{Provider: "cloudflare", Status: status, Messages: []string{message}, Err: dns.ErrUnauthorized}
	}
	return Token{AccessToken: reply.AccessToken, ExpiresIn: reply.ExpiresIn, Scope: reply.Scope}, nil
}

// Revoke ends an access token, so the authorization the customer gave does not
// outlive the one use it was for.
func (o OAuth) Revoke(ctx context.Context, accessToken string) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if accessToken == "" {
		return nil
	}
	_, status, err := o.post(ctx, pick(o.RevokeEndpoint, RevokeURL), url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}})
	if err != nil {
		return err
	}
	if status >= 300 {
		return &dns.ProviderError{Provider: "cloudflare", Status: status, Messages: []string{"the token could not be revoked"}}
	}
	return nil
}

// post sends a form to an OAuth endpoint with the client authenticated by HTTP
// Basic, the method a server-side client registers with.
func (o OAuth) post(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("cloudflare: building the request: %w", err)
	}
	request.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(o.ClientSecret))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := o.client().Do(request)
	if err != nil {
		return nil, 0, &dns.ProviderError{Provider: "cloudflare", Messages: []string{"the request did not complete"}}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, response.StatusCode, &dns.ProviderError{Provider: "cloudflare", Status: response.StatusCode, Messages: []string{"the answer could not be read"}}
	}
	return body, response.StatusCode, nil
}
