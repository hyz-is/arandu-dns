# Changelog

Everything worth knowing about a release of Arandu DNS is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]


## [0.1.0] - 2026-11-20

### Added

- `dns`: `Want`, `Record`, `Zone` and the `Provider` interface (zones, records
  at exact names, create, update; no delete). `NewPlan` reads what a zone holds
  at the wanted names and decides `create`, `update`, `exists` or `conflict` for
  each record, with the conflict codes `cname_exclusive`, `other_records`,
  `apex_protected` and `ambiguous`. An apex MX, SPF or DMARC record is changed
  only when `Want.Replace` asks. `Apply` plans again, refuses with
  `ErrPlanChanged` when the zone moved, writes only creates and updates, treats
  a duplicate as `exists`, and answers one outcome per record. `FindZone`,
  `ZoneOf`, `NormalizeContent` and the errors `ErrUnauthorized`, `ErrForbidden`,
  `ErrRateLimited`, `ErrZoneNotFound`, `ErrRecordExists` and `ErrInvalid`.
- `cloudflare`: a `dns.Provider` over the Cloudflare API with a bearer token (an
  API token with Zone Read and DNS Edit, or an OAuth access token), exact-name
  record reads, long TXT values sent as quoted chunks, no redirects followed, no
  token in any error. `OAuth`, with PKCE, for the authorization code flow:
  `AuthorizationURL`, `Exchange`, `Revoke`, `NewPKCE`, `Random`, and the scopes
  `zone.read` and `dns.write`.
- `domainconnect`: `Client.Discover` (the `_domainconnect` TXT record, from the
  whole name down, and the provider's settings), `Client.Supports`,
  `Discovery.ApplyURL` with RSA-SHA256 signing (`Signer`, `GenerateKey`,
  `PublicKeyRecords`), `Template` (`ParseTemplate`, `Validate`, `Expand`) for the
  files of the Domain-Connect/Templates repository, and `NewSafeClient`, which
  refuses internal addresses and redirects.
- `dnstest`: a `dns.Provider` in memory with `Seed`, `Holds`, `Calls` and
  `Writes`.
