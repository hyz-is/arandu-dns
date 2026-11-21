package dnstest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	dns "github.com/hyz-is/arandu-dns"
)

// Call is one call the fake received.
type Call struct {
	// Method is "Zones", "Records", "Create" or "Update".
	Method string
	Zone   string
	// Names are the names asked for in a Records call.
	Names  []string
	Record dns.Record
	ID     string
}

// Fake is a dns.Provider over memory. The zero value is not usable: build one
// with New.
type Fake struct {
	mu      sync.Mutex
	zones   []dns.Zone
	records map[string][]dns.Record
	next    int
	calls   []Call

	// Err, when set, is answered by every call until it is cleared.
	Err error
	// FailCreate, when set, is answered by Create for a record at that name.
	FailCreate map[string]error
}

var _ dns.Provider = (*Fake)(nil)

// New returns a fake that hosts the zones.
func New(zones ...dns.Zone) *Fake {
	f := &Fake{records: map[string][]dns.Record{}, FailCreate: map[string]error{}}
	for _, zone := range zones {
		f.zones = append(f.zones, zone)
		f.records[zone.ID] = nil
	}
	return f
}

// Seed adds records to a zone as if they had been there before, and answers
// them with their IDs.
func (f *Fake) Seed(zone dns.Zone, records ...dns.Record) []dns.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []dns.Record
	for _, r := range records {
		f.next++
		r.ID = fmt.Sprintf("rec-%d", f.next)
		r.Name = strings.ToLower(strings.TrimSuffix(r.Name, "."))
		f.records[zone.ID] = append(f.records[zone.ID], r)
		out = append(out, r)
	}
	return out
}

// Holds answers the records the zone has now, as a test asserts them.
func (f *Fake) Holds(zone dns.Zone) []dns.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dns.Record(nil), f.records[zone.ID]...)
}

// Calls answers every call received, in order.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Writes counts the Create and Update calls received.
func (f *Fake) Writes() int {
	n := 0
	for _, c := range f.Calls() {
		if c.Method == "Create" || c.Method == "Update" {
			n++
		}
	}
	return n
}

// Name implements dns.Provider.
func (f *Fake) Name() string { return "fake" }

// Zones implements dns.Provider.
func (f *Fake) Zones(context.Context) ([]dns.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Method: "Zones"})
	if f.Err != nil {
		return nil, f.Err
	}
	return append([]dns.Zone(nil), f.zones...), nil
}

// Records implements dns.Provider.
func (f *Fake) Records(_ context.Context, zone dns.Zone, names ...string) ([]dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Method: "Records", Zone: zone.ID, Names: append([]string(nil), names...)})
	if f.Err != nil {
		return nil, f.Err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	var out []dns.Record
	for _, r := range f.records[zone.ID] {
		if len(want) == 0 || want[r.Name] {
			out = append(out, r)
		}
	}
	return out, nil
}

// Create implements dns.Provider. It refuses an identical record at the same
// name with dns.ErrRecordExists, as a real provider does.
func (f *Fake) Create(_ context.Context, zone dns.Zone, record dns.Record) (dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Method: "Create", Zone: zone.ID, Record: record})
	if f.Err != nil {
		return dns.Record{}, f.Err
	}
	if err := f.FailCreate[record.Name]; err != nil {
		return dns.Record{}, err
	}
	for _, r := range f.records[zone.ID] {
		if r.Name == record.Name && r.Type == record.Type &&
			dns.NormalizeContent(r.Type, r.Content) == dns.NormalizeContent(record.Type, record.Content) {
			return dns.Record{}, dns.ErrRecordExists
		}
	}
	f.next++
	record.ID = fmt.Sprintf("rec-%d", f.next)
	f.records[zone.ID] = append(f.records[zone.ID], record)
	return record, nil
}

// Update implements dns.Provider.
func (f *Fake) Update(_ context.Context, zone dns.Zone, id string, record dns.Record) (dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Method: "Update", Zone: zone.ID, ID: id, Record: record})
	if f.Err != nil {
		return dns.Record{}, f.Err
	}
	for i, r := range f.records[zone.ID] {
		if r.ID == id {
			record.ID = id
			f.records[zone.ID][i] = record
			return record, nil
		}
	}
	return dns.Record{}, &dns.ProviderError{Provider: "fake", Status: 404, Messages: []string{"record not found"}}
}
