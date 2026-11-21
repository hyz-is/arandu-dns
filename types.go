package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// RecordType is a DNS record type.
type RecordType string

// The record types a plan knows the rules of. Any other type is planned by
// exact match only: equal is Exists, absent is Create, anything else is a
// Conflict.
const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
)

// Zone is a DNS zone a provider hosts.
type Zone struct {
	// ID is the provider's identifier of the zone.
	ID string
	// Name is the zone's domain: lower case, ASCII, no trailing dot.
	Name string
}

// Record is a DNS record as a provider holds it, or as a plan resolved it.
type Record struct {
	// ID is the provider's identifier. It is empty on a record that does not
	// exist yet.
	ID   string
	Type RecordType
	// Name is the full name: lower case, ASCII, no trailing dot.
	Name string
	// Content is the record's data in one string: the address of an A or AAAA,
	// the host of an MX or CNAME without a trailing dot, the text of a TXT
	// record unquoted and with its 255-byte chunks joined.
	Content string
	// TTL is in seconds. Zero is automatic.
	TTL int
	// Priority is the preference of an MX record.
	Priority int
	// Comment is a note the provider keeps with the record, when it has the
	// field.
	Comment string
}

// Want is a record the caller needs to exist.
type Want struct {
	Type RecordType
	// Name is relative to the zone: "mail", "meeng._domainkey". An empty name
	// or "@" is the zone apex. A name that ends in a dot is absolute.
	Name    string
	Content string
	// TTL in seconds; zero is automatic.
	TTL int
	// Priority is the MX preference.
	Priority int
	// Comment is stored with the record when the provider supports it.
	Comment string
	// Replace is the explicit request to change a record the plan protects: an
	// MX or SPF record at the apex, or the DMARC policy at _dmarc. Without it
	// the difference is a Conflict and nothing is touched.
	Replace bool
}

// Provider is a DNS host reached with one credential.
//
// It has no Delete on purpose. An implementation reads and writes only what it
// is asked for and never lists secrets in an error.
type Provider interface {
	// Name is the provider's short identifier, such as "cloudflare".
	Name() string
	// Zones lists the zones the credential can see.
	Zones(ctx context.Context) ([]Zone, error)
	// Records lists the records of the zone at exactly the given full names.
	// With no names it lists the whole zone.
	Records(ctx context.Context, zone Zone, names ...string) ([]Record, error)
	// Create adds a record and answers it as the provider now holds it. It
	// answers ErrRecordExists when the provider refuses a duplicate.
	Create(ctx context.Context, zone Zone, record Record) (Record, error)
	// Update replaces the record with that ID and answers it as the provider
	// now holds it.
	Update(ctx context.Context, zone Zone, id string, record Record) (Record, error)
}

// The errors a provider and a plan answer with. Wrap them with %w and test them
// with errors.Is.
var (
	// ErrUnauthorized is a credential the provider does not accept: wrong,
	// expired or revoked.
	ErrUnauthorized = errors.New("dns: the provider did not accept the credential")
	// ErrForbidden is a credential that lacks a permission the call needs.
	ErrForbidden = errors.New("dns: the credential lacks a permission the call needs")
	// ErrRateLimited is the provider asking the caller to wait.
	ErrRateLimited = errors.New("dns: the provider asked to slow down")
	// ErrZoneNotFound is a domain no zone of the credential contains.
	ErrZoneNotFound = errors.New("dns: no zone of this credential contains the domain")
	// ErrRecordExists is a create the provider refused as a duplicate.
	ErrRecordExists = errors.New("dns: the record already exists")
	// ErrInvalid is a Want that cannot be applied as written.
	ErrInvalid = errors.New("dns: invalid record")
	// ErrPlanChanged is an Apply that found the zone different from the plan
	// the person confirmed.
	ErrPlanChanged = errors.New("dns: the zone changed since the plan was made")
)

// ProviderError is a refusal or failure the provider reported. Its text carries
// the provider's own messages and never a credential.
type ProviderError struct {
	Provider string
	// Status is the HTTP status, or zero when the call never got an answer.
	Status   int
	Messages []string
	// Err is one of the sentinel errors above, or nil.
	Err error
}

// Error implements error.
func (e *ProviderError) Error() string {
	text := "dns: " + e.Provider
	if e.Status != 0 {
		text += fmt.Sprintf(" answered %d", e.Status)
	}
	if len(e.Messages) > 0 {
		text += ": " + strings.Join(e.Messages, "; ")
	}
	return text
}

// Unwrap lets errors.Is find the sentinel.
func (e *ProviderError) Unwrap() error { return e.Err }

// ZoneFinder is the optional interface of a provider that can look a zone up by
// the domain it contains without listing every zone of the credential.
type ZoneFinder interface {
	// FindZone answers the zone that contains domain, or ErrZoneNotFound.
	FindZone(ctx context.Context, domain string) (Zone, error)
}

// FindZone answers the zone of the credential that contains domain: the one
// with the longest name that domain equals or is a subdomain of. It answers
// ErrZoneNotFound when there is none. A provider that implements ZoneFinder is
// asked directly.
func FindZone(ctx context.Context, provider Provider, domain string) (Zone, error) {
	if finder, ok := provider.(ZoneFinder); ok {
		return finder.FindZone(ctx, domain)
	}
	zones, err := provider.Zones(ctx)
	if err != nil {
		return Zone{}, err
	}
	return ZoneOf(zones, domain)
}

// ZoneOf picks the zone that contains domain from a list.
func ZoneOf(zones []Zone, domain string) (Zone, error) {
	domain = canonicalName(domain)
	var best Zone
	for _, zone := range zones {
		name := canonicalName(zone.Name)
		if domain != name && !strings.HasSuffix(domain, "."+name) {
			continue
		}
		if len(name) > len(best.Name) {
			best = Zone{ID: zone.ID, Name: name}
		}
	}
	if best.ID == "" && best.Name == "" {
		return Zone{}, ErrZoneNotFound
	}
	return best, nil
}
