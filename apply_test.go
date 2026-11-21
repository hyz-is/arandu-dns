package dns_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/dnstest"
)

func TestApplyingAPlanCreatesTheRecordsAndIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := dnstest.New(zone)
	p := plan(t, f, wantSet()...)

	report, err := dns.Apply(ctx, f, p)
	if err != nil {
		t.Fatal(err)
	}
	if report.Count(dns.OutcomeCreated) != 3 || !report.Succeeded() {
		t.Fatalf("report = %+v, want three created", report.Results)
	}
	if got := len(f.Holds(zone)); got != 3 {
		t.Fatalf("zone holds %d records, want 3", got)
	}

	// The same wants again: nothing to write.
	before := f.Writes()
	again := plan(t, f, wantSet()...)
	if again.Pending() {
		t.Error("the second plan still has something pending")
	}
	report, err = dns.Apply(ctx, f, again)
	if err != nil || report.Count(dns.OutcomeExists) != 3 {
		t.Fatalf("second apply = %+v, %v; want three that exist", report.Results, err)
	}
	if f.Writes() != before {
		t.Error("the second apply wrote")
	}
}

func TestApplyRefusesAPlanTheZoneHasMovedOn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := dnstest.New(zone)
	confirmed := plan(t, f, wantSet()...)
	f.Seed(zone, dns.Record{Type: dns.TypeMX, Name: "mail.example.com", Content: "someone-else.example.org", Priority: 1})

	report, err := dns.Apply(ctx, f, confirmed)
	var changed *dns.PlanChangedError
	if !errors.As(err, &changed) || !errors.Is(err, dns.ErrPlanChanged) {
		t.Fatalf("err = %v, want a PlanChangedError", err)
	}
	if !changed.Fresh.HasConflicts() {
		t.Error("the fresh plan should show the new conflict")
	}
	if f.Writes() != 0 || len(report.Results) != 0 {
		t.Errorf("writes = %d, results = %d; want none", f.Writes(), len(report.Results))
	}
}

func TestADuplicateCreatedInTheMeantimeIsExistsNotAFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := dnstest.New(zone)
	want := dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key}
	confirmed := plan(t, f, want)
	if confirmed.Items[0].Action != dns.ActionCreate {
		t.Fatalf("action = %s, want create", confirmed.Items[0].Action)
	}

	// The record is created by somebody else while the person reads the plan:
	// Apply plans again, sees it exists and has nothing to write.
	f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=" + key})
	_, err := dns.Apply(ctx, f, confirmed)
	if !errors.Is(err, dns.ErrPlanChanged) {
		t.Fatalf("err = %v, want ErrPlanChanged", err)
	}

	// A provider that refuses the duplicate on create, seen at the moment of
	// writing, is the same outcome as the record having been there.
	g := dnstest.New(zone)
	again := plan(t, g, want)
	g.FailCreate["meeng._domainkey.example.com"] = dns.ErrRecordExists
	g.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "meeng._domainkey.example.com", Content: "p=" + key})
	report, err := dns.Apply(ctx, g, plan(t, g, want))
	if err != nil || report.Results[0].Outcome != dns.OutcomeExists {
		t.Fatalf("report = %+v, %v", report.Results, err)
	}
	_ = again
}

func TestAFailureOnOneRecordDoesNotStopTheOthers(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.FailCreate["mail.example.com"] = &dns.ProviderError{Provider: "fake", Status: 400, Messages: []string{"bad record"}}
	p := plan(t, f,
		dns.Want{Type: dns.TypeTXT, Name: "mail", Content: spf},
		dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key},
	)
	report, err := dns.Apply(context.Background(), f, p)
	if err != nil {
		t.Fatalf("err = %v, want none for a plain failure", err)
	}
	if report.Results[0].Outcome != dns.OutcomeFailed || report.Results[0].Error == "" {
		t.Errorf("first = %+v", report.Results[0])
	}
	if report.Results[1].Outcome != dns.OutcomeCreated {
		t.Errorf("second = %+v", report.Results[1])
	}
	if report.Succeeded() {
		t.Error("a report with a failure did not succeed")
	}
}

func TestARefusedCredentialStopsTheRun(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	f.FailCreate["mail.example.com"] = &dns.ProviderError{Provider: "fake", Status: 403, Err: dns.ErrForbidden}
	p := plan(t, f,
		dns.Want{Type: dns.TypeTXT, Name: "mail", Content: spf},
		dns.Want{Type: dns.TypeTXT, Name: "meeng._domainkey", Content: "p=" + key},
	)
	report, err := dns.Apply(context.Background(), f, p)
	if !errors.Is(err, dns.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(report.Results) != 2 || report.Results[1].Outcome != dns.OutcomeFailed {
		t.Errorf("results = %+v, want the rest marked as not attempted", report.Results)
	}
	if f.Writes() != 1 {
		t.Errorf("writes = %d, want the run to stop after the first", f.Writes())
	}
}

func TestNothingThePlanDidNotNameIsEverWritten(t *testing.T) {
	t.Parallel()
	f := dnstest.New(zone)
	other := f.Seed(zone,
		dns.Record{Type: dns.TypeTXT, Name: "www.example.com", Content: "keep-me"},
		dns.Record{Type: dns.TypeMX, Name: "example.com", Content: "mail.example.org", Priority: 5},
	)
	p := plan(t, f, wantSet()...)
	if _, err := dns.Apply(context.Background(), f, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if c.Method == "Update" {
			t.Errorf("an update reached %s", c.ID)
		}
		if c.Method == "Create" && (c.Record.Name == "www.example.com" || c.Record.Name == "example.com") {
			t.Errorf("a create reached %s", c.Record.Name)
		}
	}
	held := f.Holds(zone)
	for i, o := range other {
		if held[i] != o {
			t.Errorf("record %s changed", o.Name)
		}
	}
}

func TestTheProviderInterfaceCannotDelete(t *testing.T) {
	t.Parallel()
	provider := reflect.TypeOf((*dns.Provider)(nil)).Elem()
	for i := 0; i < provider.NumMethod(); i++ {
		if provider.Method(i).Name == "Delete" {
			t.Error("dns.Provider has a Delete; removal is the optional dns.Remover, called only for a confirmed replacement")
		}
	}
}
