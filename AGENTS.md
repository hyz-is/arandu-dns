# Working on Arandu DNS

This is an Arandu package made of pure Go libraries that configure the DNS of a
customer's domain for a service: the plan of the records to create, change or
leave (`dns`), the Cloudflare provider and its OAuth client (`cloudflare`), the
Domain Connect protocol (`domainconnect`) and a provider for tests (`dnstest`).
It is a Go module somebody `go get`s and imports.

It began as the package skeleton, configured as `hyz-is/dns`, and the HTTP
module the template ships was removed on purpose: there is no entity, no table,
no migration, no policy, no route, no view and no `Module` to register. Nothing
here should grow back into one. Who may configure a domain is the application's
Policy and Grant; what was configured is the application's activity log.

Read `.agents/skills/` before writing code. Each skill is a procedure, and the
one you need is named by the situation you are in.

## The gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a preference. This checkout may sit beside a Go workspace
that lists the framework repositories and does not list this one; when it does,
every command above fails before it compiles anything:

```
pattern ./...: directory prefix . does not contain modules listed in go.work
or their selected dependencies
```

Before a release, give each parser a longer fuzz run. The seeds and the inputs
that once found a defect run on every `go test`; the run is what looks past
them:

```sh
go test . -run='^$' -fuzz='^FuzzNormalizeContent$' -fuzztime=60s
go test ./domainconnect -run='^$' -fuzz='^FuzzParseTemplate$' -fuzztime=60s
```

A fuzz failure writes its input under `testdata/fuzz/<Target>/`. Commit that
file with the fix: it is the regression test.

`aru doctor` is not one of the gates. It reads applications, and exits 1 here.
It does not read this package after it is installed either, which is why
`tests/Unit/audit_test.go` compares `arandu.mod.toml` with what the code calls.

## What this repository holds

| | measured with |
| --- | --- |
| 4 packages, the root `dns`, `cloudflare`, `domainconnect` and `dnstest` | `ls -d */` |
| 0 routes, 0 tables, 1 capability (`network`) | `arandu.mod.toml`, `TestThePackageIsALibrary` |
| 0 dependencies outside the standard library | `go list -m all` |
| a fuzz test for each parser, a benchmark for each package that encodes or signs | `tests/Unit/structure_test.go` |

```
(root)         types.go normalize.go plan.go apply.go      the model, the plan, the application
cloudflare/    provider.go oauth.go                        the API and the OAuth client
domainconnect/ discover.go safe.go sign.go apply.go template.go
dnstest/       fake.go                                     a provider in memory
tests/Unit     the audit of the manifest and the shape of the library
```

## What does not exist here, on purpose

| A model reaches for | What is here instead |
| --- | --- |
| a `Delete` on `Provider`, "to clean up what we made" | nothing. `Provider` has no `Delete`, `TestTheProviderInterfaceCannotDelete` holds it. Removal is the optional `Remover`, reached only through an `ActionReplace` item of a `Want` with `Takeover` |
| storing the customer's token to retry later | the caller holds it for one request flow and revokes it. Nothing here stores a credential, and no error text carries one |
| a `Module`, a route, a table, a `Config` for the whole package | nothing. A caller imports the package it needs |
| a third-party DNS, Cloudflare or Domain Connect library | the code in this repository, written from the documentation and the specification |
| `http.Get` or the default client | the `HTTPClient` interfaces; the Cloudflare one never follows a redirect, the Domain Connect one refuses internal addresses |
| `init` that registers a provider, or a package variable assigned later | values built by `New...` and passed explicitly |
| merging an SPF record with what the customer has | a `Conflict`. Merging is a decision about their mail, and it is theirs |
| a real customer's domain, key or token in a test | `example.com`, `example.net`, and recorded response shapes with invented values |

## The properties

A change that breaks one of them is not merged, whatever else it improves.

1. **Nothing is deleted unless the plan said so, at the name it named.** There is
   no delete in the `Provider` interface and no update that reaches a record at a
   name the plan did not name. `Apply` removes records only for an
   `ActionReplace` item (a `Want` with `Takeover`), only the ones the plan listed
   at that item's own name, only through `Remover`, and puts them back when the
   create that follows fails. `Neighbours` only reads.
2. **The apex is never touched unasked.** MX, SPF and the DMARC policy at the
   apex change only with `Want.Replace`, `Takeover` included; otherwise the plan
   says `Conflict` and `Apply` writes nothing.
3. **A plan is idempotent and fresh.** Applying twice does nothing the second
   time, and `Apply` refuses with `ErrPlanChanged` when the zone is not what
   was confirmed.
4. **No credential leaks.** An error carries the provider's messages and never
   the token or the client secret; the Cloudflare client never follows a
   redirect; an OAuth authorization URL carries PKCE and no secret.
5. **The customer's DNS is untrusted input.** Discovery calls only https names,
   never a port, an IP literal or an internal address, and reads bounded bodies.
6. **`arandu.mod.toml` matches the code.** `network` is true; the other three
   are false, and `tests/Unit/audit_test.go` compares them with what the code
   calls.

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests.

Every exported symbol carries a doc comment, and the comment documents the
symbol and nothing else.

A new DNS host is a new package beside `cloudflare` that implements
`dns.Provider` and is tested against recorded responses. A new protocol for
configuring DNS without a credential goes beside `domainconnect`.

## Commits

One commit per logical change, in English, saying what changed and why. The
identity is `HYZIS <admin@hyz.is>` and is set in this repository's own git
config. Never any AI attribution. `core.hooksPath` points at
`/Users/paulorlima9/Developer/arandu-io/.githooks`.

Push, tags and releases are made when the owner has authorized them. The
repository was created from `arandu-io/package-skeleton` in the `hyz-is`
organization, and the work is on top of its first commit.
