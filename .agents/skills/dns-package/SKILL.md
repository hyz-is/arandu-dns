---
name: dns-package
description: Configure the DNS of a customer's domain from an Arandu application with Arandu DNS (Go), instead of writing a Cloudflare client or a Domain Connect flow of its own. Use when the request is to "configure the DNS automatically", "create the records for the customer", "connect the domain like Resend does", "Cloudflare token", "sign in with Cloudflare", "OAuth with Cloudflare", "Domain Connect", "GoDaddy or IONOS auto setup", "plan the DNS changes", "the customer already has an SPF or MX record", "go get github.com/hyz-is/arandu-dns", or when a project's go.mod already requires github.com/hyz-is/arandu-dns. Covers the plan, confirm and apply flow, the two Cloudflare credentials and their exact permissions, the Domain Connect flow and its signed address, the rules that keep a customer's records safe, and the mistakes that leak a token or overwrite a record.
license: MIT
metadata:
  audience: app
---

# Using Arandu DNS

Pure Go libraries. There is nothing to register in `bootstrap/app.go`, no
`aru migrate` and no service to construct for the package as a whole: import the
package and call it. The application owns what the package does not: **who may
configure a domain** (its Policy, `security.Authorize`, the Grant and the tenant
from `data.Tenant(g)`), the **activity log** of each configuration, and where a
confirmed plan waits between two requests.

```bash
go get github.com/hyz-is/arandu-dns
```

Never `replace` it to a local checkout.

## The flow

1. The person picks a way to authorize: Cloudflare with a token, Cloudflare with
   OAuth, or the provider Domain Connect found.
2. The application builds a `dns.Provider` from the credential, finds the zone
   with `dns.FindZone`, and makes the plan with `dns.NewPlan` from the records
   the domain needs as `[]dns.Want`.
3. It shows the plan: each item is `create`, `update`, `replace`, `exists` or
   `conflict`, with `Current` (what is there now, and for a `replace` what will be
   removed) and, for a conflict, a `Code` to translate
   (`cname_exclusive`, `other_records`, `apex_protected`, `ambiguous`).
4. The person confirms. The application calls `dns.Apply(ctx, provider, plan)`.
   `errors.As(err, &changed)` for `*dns.PlanChangedError` means the zone moved on:
   show `changed.Fresh` and ask again.
5. It records the result in the activity log, revokes the credential and drops it.

## Rules that are not negotiable

- **Never delete, never overwrite what was not asked.** The `Provider` has no
  delete. Removal is the optional `Remover`, used by `Apply` for a `replace` item
  of a `Want` with `Takeover`, at that item's own name, after the person saw it
  in the plan. Set `Takeover` only on names that are the service's own (its
  return path, its DKIM selector), never on the apex.
- **The apex is the customer's.** MX, SPF and the DMARC policy at the apex are
  `Conflict`s. `Want.Replace` is only for a person who read the conflict and
  chose to replace; never set it for them.
- **The credential is held for one flow.** Hold it server-side, encrypted, with a
  short expiry bound to the person and the domain, and delete it after use. Never
  put it in a log, an error shown to the person, the activity log, a URL or a
  hidden form field that is stored.
- **A pasted token is checked by use.** `cloudflare.New` refuses an empty token
  or one with spaces; `dns.ErrUnauthorized` and `dns.ErrForbidden` say which
  message to show.

## Cloudflare

| credential | how |
| --- | --- |
| a pasted API token | `cloudflare.New(token)`; the token has two permissions, both on the one zone: Zone, Zone, Read and Zone, DNS, Edit |
| OAuth | `cloudflare.OAuth{ClientID, ClientSecret, RedirectURI}`: `NewPKCE`, `Random`, `AuthorizationURL`, then `Exchange` on the callback after checking the state, and `Revoke` when done; scopes `zone.read dns.write` |

```go
provider, err := cloudflare.New(token)
zone, err := dns.FindZone(ctx, provider, domain)
plan, err := dns.NewPlan(ctx, provider, zone, wants...)
report, err := dns.Apply(ctx, provider, plan)
```

## Domain Connect

```go
client := domainconnect.Client{}
found, err := client.Discover(ctx, domain)               // ErrUnsupported: show the manual records
ok, err := client.Supports(ctx, found, providerID, serviceID) // false: the provider has not onboarded the template
address, err := found.ApplyURL(domainconnect.Request{...}, signer)
```

Show `found.Settings.DisplayName()` and `found.SyncHost()` before redirecting;
the address comes from the customer's DNS. After the redirect back, **do not
trust it as proof**: verify the records by DNS. `domainconnect.ParseTemplate`,
`Validate` and `Expand` let a test prove the template creates the records the
application expects.

## Tests

Use `dnstest.New(zone)`: `Seed` puts records in the zone, `Holds` reads them,
`Calls` and `Writes` prove what a flow did. Do not call Cloudflare from a test.

## Mistakes that cost somebody something

| the mistake | what happens |
| --- | --- |
| applying a plan from a stale page without `dns.Apply` | `Apply` plans again; calling the provider directly skips that |
| turning a `conflict` into an `update` by setting `Replace` for the person | their MX or SPF is replaced and their mail stops |
| keeping the token to "retry later" | a customer's credential sits in a database |
| following a redirect with `http.Client` defaults on the Cloudflare call | the credential is sent where the redirect points |
| calling the address in the customer's `_domainconnect` record with a default client | the server is made to call its own network |
| adding the DMARC or SPF record as a plain `Want` without checking the plan | two SPF records break SPF; the plan reports the conflict, read it |
