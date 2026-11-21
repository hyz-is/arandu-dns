# Upgrade Guide

## v0.2.0

Nothing breaks. A `Want` without `Takeover` is planned as before, and `Provider`
has the same four methods. Two things to know if you adopt the release:

- A caller that switches on `dns.Action` or `dns.Outcome` now meets `replace` and
  `replaced`. They only appear for a `Want` with `Takeover: true`.
- `dnstest.Fake.Writes` also counts deletes, which only happen on a replacement.

## v0.1.0

Nothing to upgrade from: this is the first release.
