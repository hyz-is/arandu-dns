# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the four gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

The two filters on `gofmt` are not preference. `gofmt` is the only tool in the
chain that ignores build tags, so it reads files the compiler deliberately
excludes; `testdata/` holds fixtures that are invalid on purpose.

A parser or an encoder has a fuzz or benchmark test; a new one needs its own.

## What a change has to keep true

Six properties are the reason this package is what it is. A change that breaks
one of them will not be merged, whatever else it improves.

1. **Nothing is deleted.** A provider has no delete, and an update never reaches
   a record at a name the plan did not name.
2. **The apex is never touched unasked.** An MX, an SPF or a DMARC record at the
   apex changes only when the request says `Replace`.
3. **A plan is idempotent and fresh.** Applying twice does nothing the second
   time, and `Apply` refuses a plan the zone has moved on from.
4. **No credential leaks.** Not into an error, a URL or a log, and never across
   a redirect.
5. **The customer's DNS is untrusted.** Discovery calls only public https
   names.
6. **`arandu.mod.toml` matches the code.** Adding a file write or a process
   means declaring it there in the same commit.

The package is libraries only: no `Module`, no route, no table, no policy.
Anything that needs one belongs in the application that uses it.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.
`pkg.go.dev` publishes the doc comments, and its readers are users of this
package.

Every exported symbol carries a doc comment saying what it does. The comment
documents the symbol and nothing else: no dates, no issue numbers, no
references to other repositories. Why a signature is what it is belongs there
when it is a fact about the code; anything else belongs in the pull request.

## Commits

One commit per logical change. Formatting is not mixed with behaviour, because
a diff that does both is a diff nobody reviews.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-dns.
