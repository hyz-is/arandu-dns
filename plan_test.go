package dns_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/dnstest"
)

var zone = dns.Zone{ID: "z1", Name: "example.com"}

const (
	spf  = "v=spf1 include:spf.example.net ~all"
	key  = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	dmrc = "v=DMARC1; p=none;"
)

func wantSet() []dns.Want {
	return []dns.Want{
		{Type: dns.TypeMX, Name: "mail", Content: "mx.example.net", Priority: 10},
		{Type: dns.TypeTXT, Name: "mail", Content: spf},
		{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key},
	}
}

func plan(t *testing.T, f *dnstest.Fake, wants ...dns.Want) dns.Plan {
	t.Helper()
	p, err := dns.NewPlan(context.Background(), f, zone, wants...)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

func actions(p dns.Plan) []dns.Action {
	out := make([]dns.Action, len(p.Items))
	for i, item := range p.Items {
		out[i] = item.Action
	}
	return out
}

func TestAnEmptyZoneCreatesEverything(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	p := plan(t, f, wantSet()...)
	for i, a := range actions(p) {
		if a != dns.ActionCreate {
			t.Errorf("item %d = %s, want create", i, a)
		}
	}
	if p.Items[0].Want.Name != "mail.example.com" {
		t.Errorf("name = %q, want it resolved against the zone", p.Items[0].Want.Name)
	}
	if f.Writes() != 0 {
		t.Errorf("planning wrote %d times", f.Writes())
	}
}

func TestPlanningAsksOnlyForTheNamesRequested(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	plan(t, f, wantSet()...)
	for _, c := range f.Calls() {
		if c.Method != "Records" {
			continue
		}
		if len(c.Names) != 2 {
			t.Errorf("names = %v, want the two distinct names", c.Names)
		}
		for _, n := range c.Names {
			if n != "mail.example.com" && n != "meeng._domainkey.example.com" {
				t.Errorf("asked for %q", n)
			}
		}
	}
}

func TestWhatIsThereAlreadyExists(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeMX, Name: "mail.example.com", Content: "MX.example.net.", Priority: 10},
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: `"v=spf1 include:spf.example.net ~all"`},
		dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "v=DKIM1; k=rsa; p=" + key},
	)
	p := plan(t, f, wantSet()...)
	for i, a := range actions(p) {
		if a != dns.ActionExists {
			t.Errorf("item %d = %s, want exists", i, a)
		}
	}
	if p.Pending() || p.HasConflicts() {
		t.Error("an exact zone must have nothing pending and no conflict")
	}
}

func TestAChunkedTXTRecordEqualsTheWholeOne(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 300)
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "x.example.com", Content: `"` + long[:255] + `" "` + long[255:] + `"`})
	p := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "x", Content: long})
	if got := p.Items[0].Action; got != dns.ActionExists {
		t.Errorf("action = %s, want exists", got)
	}
}

func TestADifferentRecordAtARequestedNameIsUpdated(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	old := f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=OLDKEY"})
	p := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key})
	item := p.Items[0]
	if item.Action != dns.ActionUpdate || item.Current[0].ID != old[0].ID {
		t.Fatalf("item = %+v, want an update of %s", item, old[0].ID)
	}
}

func TestPlainTXTRecordsCoexist(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "google-site-verification=abc"})
	p := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "mail", Content: "other-token=1"})
	if got := p.Items[0].Action; got != dns.ActionCreate {
		t.Errorf("action = %s, want create beside the other TXT", got)
	}
}

func TestAnMXAtANameWithOtherMXIsAConflict(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeMX, Name: "mail.example.com", Content: "feedback-smtp.example.org", Priority: 10})
	item := plan(t, f, dns.Want{Type: dns.TypeMX, Name: "mail", Content: "mx.example.net", Priority: 10}).Items[0]
	if item.Action != dns.ActionConflict || item.Code != dns.ConflictOtherRecords {
		t.Errorf("item = %s/%s, want a conflict over other records", item.Action, item.Code)
	}
}

func TestACNAMEAndOtherRecordsExcludeEachOther(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "a.example.com", Content: "hello"},
		dns.Record{Type: dns.TypeCNAME, Name: "b.example.com", Content: "target.example.net"},
	)
	p := plan(t, f,
		dns.Want{Type: dns.TypeCNAME, Name: "a", Content: "x.example.net"},
		dns.Want{Type: dns.TypeTXT, Name: "b", Content: "hello"},
	)
	for i, item := range p.Items {
		if item.Action != dns.ActionConflict || item.Code != dns.ConflictCNAME {
			t.Errorf("item %d = %s/%s, want a CNAME conflict", i, item.Action, item.Code)
		}
	}
}

func TestTheApexIsNeverTouchedWithoutBeingAsked(t *testing.T) {
	t.Parallel()
	existing := []dns.Record{
		{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
		{Type: dns.TypeTXT, Name: "example.com", Content: "v=spf1 include:_spf.example.org -all"},
		{Type: dns.TypeTXT, Name: "_dmarc.example.com", Content: "v=DMARC1; p=reject; rua=mailto:r@example.com"},
	}
	wants := []dns.Want{
		{Type: dns.TypeMX, Name: "@", Content: "mx.example.net", Priority: 10},
		{Type: dns.TypeTXT, Name: "", Content: spf},
		{Type: dns.TypeTXT, Name: "_dmarc", Content: dmrc},
	}

	f := dnstest.New(zone)
	f.Seed(zone, existing...)
	p := plan(t, f, wants...)
	for i, item := range p.Items {
		if item.Action != dns.ActionConflict || item.Code != dns.ConflictApex {
			t.Errorf("item %d = %s/%s, want an apex conflict", i, item.Action, item.Code)
		}
	}
	report, err := dns.Apply(context.Background(), f, p)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if report.Count(dns.OutcomeConflict) != 3 || f.Writes() != 0 {
		t.Errorf("conflicts = %d, writes = %d; want 3 and 0", report.Count(dns.OutcomeConflict), f.Writes())
	}
	for i, r := range f.Holds(zone) {
		if r.Content != existing[i].Content {
			t.Errorf("record %d was changed to %q", i, r.Content)
		}
	}
}

func TestReplaceIsTheExplicitRequestForTheApex(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "example.com", Content: "v=spf1 include:_spf.example.org -all"})
	p := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "@", Content: spf, Replace: true})
	if got := p.Items[0].Action; got != dns.ActionUpdate {
		t.Fatalf("action = %s, want update", got)
	}
	if _, err := dns.Apply(context.Background(), f, p); err != nil {
		t.Fatal(err)
	}
	if got := f.Holds(zone)[0].Content; got != spf {
		t.Errorf("content = %q, want the replaced SPF", got)
	}
}

func TestAMissingApexRecordCanBeCreated(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	item := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "_dmarc", Content: dmrc}).Items[0]
	if item.Action != dns.ActionCreate {
		t.Errorf("action = %s, want create: nothing is there to protect", item.Action)
	}
}

func TestTwoRecordsThatCouldBeTheOneToChangeAreAmbiguous(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "v=spf1 a -all"},
		dns.Record{Type: dns.TypeTXT, Name: "mail.example.com", Content: "v=spf1 mx -all"},
	)
	item := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "mail", Content: spf}).Items[0]
	if item.Action != dns.ActionConflict || item.Code != dns.ConflictAmbiguous {
		t.Errorf("item = %s/%s, want ambiguous", item.Action, item.Code)
	}
}

func TestInvalidWantsAreRefusedBeforeAnythingIsRead(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]dns.Want{
		"outside the zone":  {Type: dns.TypeTXT, Name: "x.other.org.", Content: "a"},
		"no content":        {Type: dns.TypeTXT, Name: "x", Content: " "},
		"no type":           {Name: "x", Content: "a"},
		"control character": {Type: dns.TypeTXT, Name: "x", Content: "a\r\nb"},
		"negative ttl":      {Type: dns.TypeTXT, Name: "x", Content: "a", TTL: -1},
	} {
		f := dnstest.New(zone)
		_, err := dns.NewPlan(context.Background(), f, zone, want)
		if !errors.Is(err, dns.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("%s: the provider was called", name)
		}
	}
}

func TestRecordsOfOtherNamesTheProviderReturnsAreIgnored(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "unrelated.example.com", Content: "v=spf1 -all"})
	p := plan(t, f, dns.Want{Type: dns.TypeTXT, Name: "mail", Content: spf})
	if got := p.Items[0].Action; got != dns.ActionCreate {
		t.Errorf("action = %s", got)
	}
}

func TestFindZonePicksTheLongestMatch(t *testing.T) {
	t.Parallel()
	zones := []dns.Zone{{ID: "1", Name: "example.com"}, {ID: "2", Name: "send.example.com"}, {ID: "3", Name: "example.org"}}
	got, err := dns.ZoneOf(zones, "A.Send.Example.com.")
	if err != nil || got.ID != "2" {
		t.Errorf("zone = %+v, %v; want send.example.com", got, err)
	}
	if _, err := dns.ZoneOf(zones, "notexample.com"); !errors.Is(err, dns.ErrZoneNotFound) {
		t.Errorf("err = %v, want ErrZoneNotFound for a name that only ends the same", err)
	}
	f := dnstest.New(zones...)
	if z, err := dns.FindZone(context.Background(), f, "example.org"); err != nil || z.ID != "3" {
		t.Errorf("FindZone = %+v, %v", z, err)
	}
}
