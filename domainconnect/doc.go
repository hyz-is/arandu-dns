// Package domainconnect implements the application side of Domain Connect, the
// open standard (an IETF draft) with which a service sends a customer to their
// DNS provider to apply a template of records with one confirmation, with no
// credential ever reaching the service.
//
// It covers the synchronous flow, the one DNS providers such as Cloudflare,
// GoDaddy and IONOS open to a service that has onboarded its template:
//
//   - Client.Discover finds the DNS provider of a domain by the _domainconnect
//     TXT record, and reads its settings.
//   - Client.Supports asks that provider whether it has the service's template.
//   - Discovery.ApplyURL builds the address the customer's browser is sent to,
//     with the variables of the template and a signature made with the
//     service's private key (Signer), as the providers that require one check
//     against the public key in DNS (PublicKeyRecords).
//   - Template reads, validates and expands the JSON template a service
//     submits to the Domain-Connect/Templates repository, so a test can prove
//     that the template creates the records the application expects.
//
// The address of the settings and of the apply page come from the customer's own
// DNS, so Client's default HTTP client refuses to connect to a private,
// loopback or link-local address, does not follow redirects and reads a
// bounded body. The apply page is where the customer is sent: a caller shows
// its host before redirecting.
package domainconnect
