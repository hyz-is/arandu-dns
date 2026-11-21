// Package cloudflare is a dns.Provider over the Cloudflare API, and the OAuth
// 2.0 client that lets a Cloudflare customer authorize an application to edit
// the DNS of their zones.
//
// Two credentials work, and the provider treats them alike, as a bearer token:
//
//   - An API token the customer creates and pastes, with two permissions,
//     both restricted to the one zone: Zone, Zone, Read (to find the zone) and
//     Zone, DNS, Edit (to read and write its records).
//   - An OAuth access token, from OAuth.Exchange, with the scopes zone.read and
//     dns.write that the customer approved on Cloudflare's consent screen.
//
// Nothing here stores a credential. A Provider holds the token for as long as
// the caller holds the Provider, and an error never carries it.
package cloudflare
