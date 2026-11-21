package dns_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/dnstest"
)

// takeoverSet is what a service that owns its names asks for: a CNAME for the
// return path and a DKIM key, each with Takeover.
func takeoverSet() []dns.Want {
	return []dns.Want{
		{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true},
		{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key, Takeover: true},
	}
}

func deletes(f *dnstest.Fake) int {
	n := 0
	for _, c := range f.Calls() {
		if c.Method == "Delete" {
			n++
		}
	}
	return n
}

func TestTheSameRecordIsLeftAloneEvenWithTakeover(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeCNAME, Name: "mail.example.com", Content: "return.example.net"},
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=" + key},
	)
	p := plan(t, f, takeoverSet()...)
	if got := actions(p); got[0] != dns.ActionExists || got[1] != dns.ActionExists {
		t.Fatalf("actions = %v, want exists twice", got)
	}
	if _, err := dns.Apply(context.Background(), f, p); err != nil || f.Writes() != 0 {
		t.Errorf("apply wrote %d times, err %v", f.Writes(), err)
	}
}

func TestAnotherValueAtTheSameNameIsUpdatedInPlace(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	old := f.Seed(zone,
		dns.Record{Type: dns.TypeCNAME, Name: "mail.example.com", Content: "other.example.org"},
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=OLDKEY"},
	)
	p := plan(t, f, takeoverSet()...)
	for i, item := range p.Items {
		if item.Action != dns.ActionUpdate || item.Current[0].ID != old[i].ID {
			t.Fatalf("item %d = %+v, want an update of %s", i, item, old[i].ID)
		}
	}
	report, err := dns.Apply(context.Background(), f, p)
	if err != nil || report.Count(dns.OutcomeUpdated) != 2 || deletes(f) != 0 {
		t.Fatalf("report = %+v, deletes = %d, err = %v", report.Results, deletes(f), err)
	}
}

func TestACNAMEWhereATXTGoesIsReplacedAndTheOtherWayAround(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	seeded := f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "mail.example.com", Content: "feedback-smtp.example.org", Priority: 10},
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "v=spf1 include:amazonses.com ~all"},
		dns.Record{Type: dns.TypeCNAME, Name: "meeng._domainkey.example.com", Content: "dkim.other.example.org"},
		dns.Record{Type: dns.TypeTXT, Name: "www.example.com", Content: "keep-me"},
	)
	p := plan(t, f, takeoverSet()...)
	for i, item := range p.Items {
		if item.Action != dns.ActionReplace {
			t.Fatalf("item %d = %s, want replace", i, item.Action)
		}
	}
	if len(p.Items[0].Current) != 2 || len(p.Items[1].Current) != 1 {
		t.Errorf("the plan lists %d and %d records to remove, want 2 and 1", len(p.Items[0].Current), len(p.Items[1].Current))
	}
	if !p.Pending() || p.Count(dns.ActionReplace) != 2 {
		t.Error("a replacement must count as pending")
	}
	if f.Writes() != 0 {
		t.Fatal("planning wrote")
	}

	report, err := dns.Apply(context.Background(), f, p)
	if err != nil || report.Count(dns.OutcomeReplaced) != 2 || !report.Succeeded() {
		t.Fatalf("report = %+v, err = %v", report.Results, err)
	}
	if len(report.Results[0].Removed) != 2 || report.Results[1].Removed[0].ID != seeded[2].ID {
		t.Errorf("the report did not say what was removed: %+v", report.Results)
	}
	held := f.Holds(zone)
	var names []string
	for _, r := range held {
		names = append(names, string(r.Type)+" "+r.Name)
	}
	if got := strings.Join(names, "|"); got != "TXT www.example.com|CNAME mail.example.com|TXT meeng._domainkey.example.com" {
		t.Errorf("the zone holds %s", got)
	}
	// Planning again finds nothing to do.
	if plan(t, f, takeoverSet()...).Pending() {
		t.Error("the plan after the replacement still has work")
	}
}

func TestSeveralRecordsThatCouldBeTheOneAreAllReplacedWithTakeover(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=ONE"},
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=TWO"},
		dns.Record{Type: dns.TypeMX, Name: "example.net.example.com", Content: "x.example.org", Priority: 1},
	)
	item := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key, Takeover: true}).Items[0]
	if item.Action != dns.ActionReplace || len(item.Current) != 2 {
		t.Fatalf("item = %s with %d current, want a replacement of both", item.Action, len(item.Current))
	}
}

func TestWithoutTakeoverNothingChangesFromBefore(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "hello"},
		dns.Record{Type: dns.TypeCNAME, Name: "meeng._domainkey.example.com", Content: "dkim.other.example.org"},
	)
	p := plan(t, f,
		dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net"},
		dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key},
	)
	for i, item := range p.Items {
		if item.Action != dns.ActionConflict {
			t.Errorf("item %d = %s, want a conflict without Takeover", i, item.Action)
		}
	}
	if _, err := dns.Apply(context.Background(), f, p); err != nil || f.Writes() != 0 || deletes(f) != 0 {
		t.Errorf("writes = %d, deletes = %d, err = %v", f.Writes(), deletes(f), err)
	}
}

func TestTakeoverNeverReachesTheApexUnlessReplaceAsksToo(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
		dns.Record{Type: dns.TypeTXT, Name: "example.com", Content: "v=spf1 include:_spf.example.org -all"},
		dns.Record{Type: dns.TypeTXT, Name: "_dmarc.example.com", Content: "v=DMARC1; p=reject"},
	)
	wants := []dns.Want{
		{Type: dns.TypeMX, Name: "@", Content: "mx.example.net", Priority: 10, Takeover: true},
		{Type: dns.TypeTXT, Name: "@", Content: spf, Takeover: true},
		{Type: dns.TypeTXT, Name: "_dmarc", Content: dmrc, Takeover: true},
	}
	p := plan(t, f, wants...)
	for i, item := range p.Items {
		if item.Action != dns.ActionConflict || item.Code != dns.ConflictApex {
			t.Errorf("item %d = %s/%s, want an apex conflict", i, item.Action, item.Code)
		}
	}
	// A subdomain's DMARC is not the zone's policy: with Takeover it is replaced.
	g := dnstest.New(zone)
	g.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "_dmarc.updates.example.com", Content: "v=DMARC1; p=reject"})
	sub := plan(t, g, dns.Want{Type: dns.TypeTXT, Name: "_dmarc.updates", Content: dmrc, Takeover: true}).Items[0]
	if sub.Action != dns.ActionUpdate {
		t.Errorf("a subdomain's DMARC = %s, want update", sub.Action)
	}
}

func TestAnMXAtAWantedNameWithOtherMXIsReplacedWithTakeover(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "updates.example.com", Content: "inbound.other.example.org", Priority: 10},
		dns.Record{Type: dns.TypeMX, Name: "updates.example.com", Content: "inbound2.other.example.org", Priority: 20},
	)
	item := plan(t, f, dns.Want{Type: dns.TypeMX, Name: "updates", Content: "mx.example.net", Priority: 10, Takeover: true}).Items[0]
	if item.Action != dns.ActionReplace || len(item.Current) != 2 {
		t.Fatalf("item = %s with %d current", item.Action, len(item.Current))
	}
}

func TestAFailedCreateAfterTheRemovalPutsTheRecordsBack(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "v=spf1 include:amazonses.com ~all", TTL: 300})
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true})
	// The provider refuses the wanted CNAME and accepts the restored TXT.
	failing := &failOnce{Fake: f, name: "mail.example.com", kind: dns.TypeCNAME}
	report, err := dns.Apply(context.Background(), failing, p)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Results[0]
	if r.Outcome != dns.OutcomeFailed || !r.Restored || len(r.Removed) != 1 {
		t.Fatalf("result = %+v, want a failure with the record restored", r)
	}
	held := f.Holds(zone)
	if len(held) != 1 || held[0].Type != dns.TypeTXT || held[0].Content != "v=spf1 include:amazonses.com ~all" {
		t.Errorf("the zone holds %+v, want the TXT back", held)
	}
}

// failOnce refuses the creation of one kind of record at one name.
type failOnce struct {
	*dnstest.Fake
	name string
	kind dns.RecordType
}

func (f *failOnce) Create(ctx context.Context, zone dns.Zone, record dns.Record) (dns.Record, error) {
	if record.Name == f.name && record.Type == f.kind {
		return dns.Record{}, &dns.ProviderError{Provider: "fake", Status: 400, Messages: []string{"invalid"}}
	}
	return f.Fake.Create(ctx, zone, record)
}

func TestAProviderThatCannotRemoveFailsTheReplacementAndChangesNothing(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "hello"})
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true})
	report, err := dns.Apply(context.Background(), onlyProvider{f}, p)
	if err != nil {
		t.Fatal(err)
	}
	if r := report.Results[0]; r.Outcome != dns.OutcomeFailed || !strings.Contains(r.Error, "cannot remove") {
		t.Errorf("result = %+v", r)
	}
	if f.Writes() != 0 {
		t.Error("the replacement wrote without a Remover")
	}
}

// onlyProvider hides everything but dns.Provider.
type onlyProvider struct{ dns.Provider }

func TestADeniedRemovalStopsTheRunAndKeepsWhatWasThere(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.NoDelete = true
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "hello"})
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true})
	_, err := dns.Apply(context.Background(), f, p)
	if !errors.Is(err, dns.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if held := f.Holds(zone); len(held) != 1 || held[0].Content != "hello" {
		t.Errorf("the zone holds %+v", held)
	}
}

func TestAReplacementOnlyReachesTheNamesOfThePlan(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "hello"},
		dns.Record{Type: dns.TypeTXT, Name: "resend._domainkey.example.com", Content: "p=OTHER"},
		dns.Record{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
	)
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true})
	if _, err := dns.Apply(context.Background(), f, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if c.Method == "Delete" && c.ID != "rec-1" {
			t.Errorf("a removal reached %s", c.ID)
		}
	}
	if len(f.Holds(zone)) != 3 {
		t.Errorf("the zone holds %d records, want the 2 untouched and the CNAME", len(f.Holds(zone)))
	}
}

func TestNeighboursAreWhatLooksLikeAnotherServicesAndIsNotInThePlan(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "send.updates.example.com", Content: "feedback-smtp.sa-east-1.amazonses.com", Priority: 10},
		dns.Record{Type: dns.TypeTXT, Name: "send.updates.example.com", Content: "v=spf1 include:amazonses.com ~all"},
		dns.Record{Type: dns.TypeTXT, Name: "resend._domainkey.updates.example.com", Content: "p=MIGfMA0GCSqGSIb3DQEB"},
		dns.Record{Type: dns.TypeCNAME, Name: "rsend.updates.example.com", Content: "rsend-sae1.forge.rmta.net"},
		dns.Record{Type: dns.TypeMX, Name: "updates.example.com", Content: "inbound-smtp.sa-east-1.amazonaws.com", Priority: 10},
		dns.Record{Type: dns.TypeCNAME, Name: "mail.updates.example.com", Content: "old.example.org"},
		dns.Record{Type: dns.TypeA, Name: "app.updates.example.com", Content: "192.0.2.1"},
		dns.Record{Type: dns.TypeCNAME, Name: "links.updates.example.com", Content: "links2.resend-dns.com"},
		dns.Record{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
	)
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail.updates", Content: "return.example.net", Takeover: true})
	got, err := dns.Neighbours(context.Background(), f, p, "updates.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, string(r.Type)+" "+r.Name)
	}
	want := "MX send.updates.example.com|TXT send.updates.example.com|TXT resend._domainkey.updates.example.com|CNAME rsend.updates.example.com|MX updates.example.com"
	if strings.Join(names, "|") != want {
		t.Errorf("neighbours = %v\nwant       %s", names, want)
	}
	if f.Writes() != 0 {
		t.Error("looking wrote")
	}
}

func TestAtTheApexTheOwnersMailIsNotAnotherService(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
		dns.Record{Type: dns.TypeTXT, Name: "example.com", Content: "v=spf1 include:_spf.example.org -all"},
		dns.Record{Type: dns.TypeTXT, Name: "resend._domainkey.example.com", Content: "p=MIGfMA0GCSqGSIb3DQEB"},
	)
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net", Takeover: true})
	got, err := dns.Neighbours(context.Background(), f, p, "example.com")
	if err != nil || len(got) != 1 || got[0].Name != "resend._domainkey.example.com" {
		t.Errorf("neighbours = %+v, %v; want only the DKIM key", got, err)
	}
}

func TestAProviderThatCannotListHasNoNeighbours(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	p := plan(t, f, dns.Want{Type: dns.TypeCNAME, Name: "mail", Content: "return.example.net"})
	got, err := dns.Neighbours(context.Background(), onlyProvider{f}, p, "example.com")
	if err != nil || got != nil {
		t.Errorf("neighbours = %+v, %v", got, err)
	}
}
