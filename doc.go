// Package dns plans and applies the DNS records a service needs on a customer's
// domain, without ever deleting or rewriting what the customer already has.
//
// The caller states the records it wants as []Want. Plan reads what a Provider
// holds at exactly those names and answers what would be created, what would be
// changed, what is already right and what conflicts. Apply carries out a plan
// the person confirmed, and answers what happened to each record.
//
// The rules a plan follows, and the tests hold:
//
//   - A Provider cannot delete. The interface has no such method, so no code
//     path in this package or in an application using it can.
//   - Only the names asked for are read or written.
//   - A record at the zone apex that decides where mail goes or who may send
//     it (MX, SPF, and the DMARC policy at _dmarc) is never changed unless the
//     Want says Replace. Without it, a difference is a Conflict for the person
//     to decide.
//   - Applying a plan twice does nothing the second time: what exists is
//     reported as Exists.
//   - Apply plans again before it writes, and refuses with ErrPlanChanged when
//     the zone is no longer what the person confirmed.
//
// The providers are subpackages: cloudflare talks to the Cloudflare API with a
// token or an OAuth access token the caller holds for the length of one
// request; domainconnect implements the Domain Connect protocol, where the
// customer applies a template at their DNS provider and no credential reaches
// the application. dnstest holds a provider for tests that touches no network.
package dns
