<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu DNS

Pure Go libraries that configure the DNS of a customer's domain for a service:
the customer clicks, the records appear, and nothing the customer already had is
deleted or rewritten behind their back.

It is a set of libraries. It registers no route, owns no table and decides no
authorization, so there is nothing to wire in `bootstrap/app.go`, nothing to
construct for the package as a whole, and no `aru migrate` to run. An
application imports the package it needs and calls it. The application decides
who may configure a domain (its own Policy and Grant), and records the act in
its activity log.

## Install

```bash
go get github.com/hyz-is/arandu-dns
```

The module requires nothing outside the standard library. `arandu.mod.toml`
declares the network capability, because the providers call out; it declares no
filesystem, no process and no migration.

| package | what it does |
| --- | --- |
| `arandu-dns` | the records a service wants (`dns.Want`), the plan of what to create, change or leave (`dns.NewPlan`), and the application of a confirmed plan (`dns.Apply`) |
| `arandu-dns/cloudflare` | a provider over the Cloudflare API with a token, and the OAuth client that lets a customer authorize with their own Cloudflare account |
| `arandu-dns/domainconnect` | Domain Connect, the synchronous flow: discover the DNS provider of a domain, build the signed apply address, read and expand a template |
| `arandu-dns/dnstest` | a provider in memory, for tests, that records every call |

## The rules a plan keeps

- A `dns.Provider` has no delete. Nothing in this module can remove a record.
- Only the names asked for are read or written.
- A record at the apex that decides where mail goes or who may send it (MX, SPF,
  and the DMARC policy at `_dmarc`) is never changed unless the `Want` says
  `Replace: true`. Without it, a difference is a `Conflict` the person decides.
- A CNAME never shares a name; two SPF or DMARC records never appear; an MX
  never joins MX records that point elsewhere. Each is a `Conflict`.
- Applying twice does nothing the second time.
- `dns.Apply` plans again before writing and refuses with `dns.ErrPlanChanged`
  (a `*dns.PlanChangedError` carrying the new plan) if the zone is no longer
  what the person confirmed.

## Plan, confirm, apply

```go
import (
	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/cloudflare"
)

provider, err := cloudflare.New(token) // the customer's token, held for this request flow
zone, err := dns.FindZone(ctx, provider, "send.acme.com")

plan, err := dns.NewPlan(ctx, provider, zone,
	dns.Want{Type: dns.TypeMX, Name: "mail.send", Content: "mx.example.net", Priority: 10},
	dns.Want{Type: dns.TypeTXT, Name: "mail.send", Content: "v=spf1 include:spf.example.net ~all"},
	dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey.send", Content: "p=MIIB..."},
)
// Show plan.Items to the person: create, update, exists or conflict, each with
// what is there now. They confirm.

report, err := dns.Apply(ctx, provider, plan)
var changed *dns.PlanChangedError
if errors.As(err, &changed) {
	// The zone moved on: show changed.Fresh and ask again.
}
// report.Results has one outcome per record: created, updated, exists,
// conflict or failed, with the provider's own message for a failure.
```

A `Want` name is relative to the zone (`"mail"`, `"@"` for the apex) unless it
ends in a dot.

## Cloudflare

Two credentials work, and the provider treats both as a bearer token.

**An API token the customer pastes.** In the Cloudflare dashboard, under My
Profile, API Tokens, Create Token, Create Custom Token, with exactly these
permissions and the zone resource set to the one zone:

| permission | why |
| --- | --- |
| Zone, Zone, Read | `GET /zones`, to find the zone |
| Zone, DNS, Edit | read and write the zone's records |

`Zone, DNS, Edit` is the "DNS Write" permission of the API. A token with
anything more is a token the customer should not have given. The application
uses it for one request flow and does not store it.

**OAuth with the customer's own account.** Cloudflare lets any account create an
OAuth client (Manage Account, OAuth clients). A server-side client uses the
authorization code flow with a client secret; this package adds PKCE.

```go
oauth := cloudflare.OAuth{ClientID: id, ClientSecret: secret, RedirectURI: callback}
pkce, _ := cloudflare.NewPKCE()
state, _ := cloudflare.Random(24)
address, _ := oauth.AuthorizationURL(state, pkce) // send the browser here; keep state and pkce.Verifier server-side
// on the callback, after checking state:
token, err := oauth.Exchange(ctx, code, pkce)
provider, _ := cloudflare.New(token.AccessToken)
// ... plan and apply ...
_ = oauth.Revoke(ctx, token.AccessToken) // the authorization does not outlive its use
```

The scopes are `zone.read` and `dns.write` (`cloudflare.DefaultScopes`), the
same two permissions. Refresh tokens are never requested. A client that any
Cloudflare user may authorize must be made public, which Cloudflare requires to
be verified by a TXT record on the client's domain, and which cannot be undone.

## Domain Connect

Domain Connect is the standard (an IETF draft) with which a service sends the
customer to their DNS provider, who shows what will be created and applies it;
no credential reaches the service. Cloudflare, GoDaddy, IONOS and others offer
it once a service has onboarded its template with them.

```go
import "github.com/hyz-is/arandu-dns/domainconnect"

client := domainconnect.Client{} // system resolver, an HTTP client that refuses internal addresses
found, err := client.Discover(ctx, "send.acme.com") // found.Domain "acme.com", found.Host "send"
ok, err := client.Supports(ctx, found, "meeng.dev", "sending")
// Show found.Settings.DisplayName() and found.SyncHost() to the person, then:
address, err := found.ApplyURL(domainconnect.Request{
	ProviderID: "meeng.dev", ServiceID: "sending",
	Variables:   map[string]string{"dkim": publicKey},
	RedirectURI: "https://meeng.dev/painel/dominios/7/conectado", State: state,
}, signer)
```

`domainconnect.NewSigner` takes the service's RSA private key and the host of
its public key (`_dck1`). `Signer.PublicKeyRecords` answers the TXT values to
publish there, in the `syncPubKeyDomain` of the template. Requests are signed
with RSA-SHA256 over the query before `key` and `sig`, and `sig` comes last, as
Cloudflare requires.

`domainconnect.ParseTemplate`, `Template.Validate` and `Template.Expand` read the
template a service submits to the
[Domain-Connect/Templates](https://github.com/Domain-Connect/Templates)
repository and say which records it creates, so a test can compare them with
what the application expects.

The addresses discovery follows come from the customer's own DNS. The default
HTTP client refuses a private, loopback or link-local address at the moment of
connecting, does not follow redirects, and reads a bounded body; discovery
refuses an address that is not an https name.

## Tests

`dnstest.New(zone)` is a `dns.Provider` over memory with `Seed`, `Holds`,
`Calls` and `Writes`. The Cloudflare provider is tested against recorded
response shapes served by a local test server; no test calls the real API.

## Licence

MIT.
