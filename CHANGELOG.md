# Changelog

Everything worth knowing about a release of Arandu DNS is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.2.0] - 2026-11-21

### Added

- `Want.Takeover`: the name is the caller's. What else holds it with other data
  is replaced instead of being a `Conflict`: a CNAME and other records that
  cannot share the name (either way), several records that could be the one to
  change, other MX records at a wanted MX name. One record of the same kind is
  still an `update` in place. A protected apex record still needs `Want.Replace`.
- `ActionReplace` and `OutcomeReplaced`. A replace item lists in `Item.Current`
  the records that will be removed, so the person sees them before confirming;
  `Plan.Pending` counts it. `Result.Removed` says what was removed and
  `Result.Restored` that a failed create put it back.
- `Remover`, the optional interface of a provider that can remove a record, and
  `ErrCannotRemove`. `Provider` itself still has no `Delete`.
- `Lister` and `Neighbours`: the records at and under a name that look like
  another sending service's (an MX or SPF at the name, DKIM keys, return-path
  aliases such as `send` and `rsend`), outside the plan, for a screen to show.
  It only reads.
- `cloudflare`: `Provider.Delete` and `Provider.RecordsUnder` (the `name.endswith`
  filter).
- `dnstest`: `Fake.Delete`, `Fake.RecordsUnder` and `Fake.NoDelete`; `Writes`
  counts deletes.

### Changed

- Without `Takeover` nothing changes: every plan decides as in 0.1.0.

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
