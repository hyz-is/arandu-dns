package domainconnect_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-dns/domainconnect"
)

func signer(t *testing.T) *domainconnect.Signer {
	t.Helper()
	pemKey, err := domainconnect.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := domainconnect.NewSigner(pemKey, "_dck1")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func discovery(t *testing.T, domain string) domainconnect.Discovery {
	t.Helper()
	client, _ := cloudflare(t)
	d, err := client.Discover(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTheApplyURLIsSignedOverTheQueryBeforeTheKeyAndTheSignature(t *testing.T) {
	t.Parallel()
	s := signer(t)
	raw, err := discovery(t, "send.example.com").ApplyURL(domainconnect.Request{
		ProviderID: "example.com", ServiceID: "sending",
		Variables:   map[string]string{"dkim": "MIIB+/=abc d", "selector": "ex"},
		RedirectURI: "https://example.com/domains/7/connected", State: "s t&ate",
	}, s)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(raw, "https://dash.cloudflare.com/domainconnect/v2/domainTemplates/providers/example.com/services/sending/apply?") {
		t.Fatalf("url = %s", raw)
	}
	query := raw[strings.Index(raw, "?")+1:]
	sigAt := strings.LastIndex(query, "&sig=")
	keyAt := strings.LastIndex(query, "&key=")
	if sigAt < 0 || keyAt < 0 || keyAt > sigAt || strings.Contains(query[sigAt+1:], "&") {
		t.Fatalf("key and sig must close the query, sig last: %s", query)
	}
	signed := query[:keyAt]

	parsed, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"domain": "example.com", "host": "send", "dkim": "MIIB+/=abc d", "selector": "ex",
		"redirect_uri": "https://example.com/domains/7/connected", "state": "s t&ate", "key": "_dck1",
	} {
		if parsed.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, parsed.Get(k), v)
		}
	}

	// A provider verifies with the public key it finds in DNS.
	var encoded strings.Builder
	records, err := s.PublicKeyRecords()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range records {
		prefix := "p=" + string(rune('1'+i)) + ",a=RS256,d="
		if !strings.HasPrefix(r, prefix) || len(r) > 255 {
			t.Errorf("record %d = %.30q... is not a short numbered chunk", i, r)
		}
		encoded.WriteString(strings.TrimPrefix(r, prefix))
	}
	der, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(parsed.Get("sig"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, sum[:], signature); err != nil {
		t.Errorf("the signature does not verify over %q: %v", signed, err)
	}
}

func TestTheRootDomainHasNoHostParameter(t *testing.T) {
	t.Parallel()
	raw, err := discovery(t, "example.com").ApplyURL(domainconnect.Request{ProviderID: "example.com", ServiceID: "sending"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "host=") || strings.Contains(raw, "sig=") {
		t.Errorf("url = %s, want no host and no signature", raw)
	}
}

func TestVariablesCannotShadowTheProtocol(t *testing.T) {
	t.Parallel()
	d := discovery(t, "example.com")
	for _, name := range []string{"domain", "host", "redirect_uri", "STATE", "sig", "key", "groupId"} {
		_, err := d.ApplyURL(domainconnect.Request{ProviderID: "example.com", ServiceID: "sending", Variables: map[string]string{name: "x"}}, nil)
		if err == nil {
			t.Errorf("variable %q was accepted", name)
		}
	}
}

func TestARedirectThatIsNotAWebAddressIsRefused(t *testing.T) {
	t.Parallel()
	d := discovery(t, "example.com")
	for _, redirect := range []string{"javascript:alert(1)", "//evil.example", "/relative", "ftp://x.example/a"} {
		_, err := d.ApplyURL(domainconnect.Request{ProviderID: "example.com", ServiceID: "sending", RedirectURI: redirect}, nil)
		if err == nil {
			t.Errorf("redirect %q was accepted", redirect)
		}
	}
}

func TestGroupsAreJoinedAndTheTemplateMustBeNamed(t *testing.T) {
	t.Parallel()
	d := discovery(t, "example.com")
	raw, err := d.ApplyURL(domainconnect.Request{ProviderID: "example.com", ServiceID: "sending", GroupIDs: []string{"mail", "dmarc"}}, nil)
	if err != nil || !strings.Contains(raw, "groupId=mail%2Cdmarc") {
		t.Errorf("url = %s, %v", raw, err)
	}
	if _, err := d.ApplyURL(domainconnect.Request{}, nil); err == nil {
		t.Error("a request naming no template was accepted")
	}
}

func TestAKeyThatIsNotAnRSAPrivateKeyOfEnoughBitsIsRefused(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"empty": "", "not pem": "hello",
		"garbage": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	} {
		if _, err := domainconnect.NewSigner([]byte(input), "_dck1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	pemKey, _ := domainconnect.GenerateKey()
	for _, host := range []string{"", "a b", "a&b", "a/b"} {
		if _, err := domainconnect.NewSigner(pemKey, host); err == nil {
			t.Errorf("key host %q accepted", host)
		}
	}
}

func BenchmarkApplyURL(b *testing.B) {
	pemKey, _ := domainconnect.GenerateKey()
	s, _ := domainconnect.NewSigner(pemKey, "_dck1")
	client, _ := cloudflare(b)
	d, err := client.Discover(b.Context(), "example.com")
	if err != nil {
		b.Skip("discovery needs the recorded files")
	}
	request := domainconnect.Request{ProviderID: "example.com", ServiceID: "sending", Variables: map[string]string{"dkim": strings.Repeat("A", 392)}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.ApplyURL(request, s); err != nil {
			b.Fatal(err)
		}
	}
}
