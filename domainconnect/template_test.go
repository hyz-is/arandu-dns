package domainconnect_test

import (
	"os"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-dns/domainconnect"
)

func load(t *testing.T, name string) domainconnect.Template {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tpl, err := domainconnect.ParseTemplate(f)
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestTheExampleTemplateIsValidAndNamedForItsFile(t *testing.T) {
	t.Parallel()
	tpl := load(t, "example.sending.json")
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	if tpl.FileName() != "example.com.sending.json" {
		t.Errorf("file name = %q", tpl.FileName())
	}
	if got := strings.Join(tpl.Variables(), ","); got != "dkim" {
		t.Errorf("variables = %q, want dkim", got)
	}
}

func TestExpandingTheTemplateGivesTheRecordsItCreates(t *testing.T) {
	t.Parallel()
	tpl := load(t, "example.sending.json")
	records, err := tpl.Expand("example.com", "", map[string]string{"dkim": "KEY"})
	if err != nil {
		t.Fatal(err)
	}
	want := []domainconnect.Expanded{
		{Type: "MX", GroupID: "mail", Host: "mail", Content: "mx.example.net", TTL: 3600, Priority: 10},
		{Type: "TXT", GroupID: "mail", Host: "mail", Content: "v=spf1 include:spf.example.net ~all"},
		{Type: "TXT", GroupID: "mail", Host: "ex._domainkey", Content: "p=KEY", TTL: 3600},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %+v", records)
	}
	for i := range want {
		if records[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, records[i], want[i])
		}
	}
}

func TestOnASubdomainTheHostsAreRelativeToIt(t *testing.T) {
	t.Parallel()
	records, err := load(t, "example.sending.json").Expand("example.com", "send", map[string]string{"dkim": "KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Host != "mail.send" || records[2].Host != "ex._domainkey.send" {
		t.Errorf("hosts = %q, %q", records[0].Host, records[2].Host)
	}
}

func TestAMissingVariableIsAnErrorNotAnEmptyValue(t *testing.T) {
	t.Parallel()
	_, err := load(t, "example.sending.json").Expand("example.com", "", nil)
	if err == nil || !strings.Contains(err.Error(), "dkim") {
		t.Errorf("err = %v, want one naming dkim", err)
	}
	if _, err := load(t, "example.sending.json").Expand("example.com", "", map[string]string{"dkim": "x", "domain": "evil.example"}); err == nil {
		t.Error("a built-in variable was overridden")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	t.Parallel()
	tpl := domainconnect.Template{
		ProviderID: "nodots", ServiceID: "has space", SyncBlock: true, WarnPhishing: true,
		Records: []domainconnect.TemplateRecord{
			{Type: "TXT", Host: "mail", Data: "v=spf1 -all", TTL: "3600"},
			{Type: "APEXCNAME", Host: "@", PointsTo: "x.example.net"},
			{Type: "CNAME", PointsTo: "x.example.net", TTL: "300"},
			{Type: "MX", Host: "mail"},
			{Type: "SRV"},
		},
	}
	err := tpl.Validate()
	if err == nil {
		t.Fatal("an invalid template passed")
	}
	for _, want := range []string{
		"providerId", "serviceId", "providerName", "syncBlock", "syncPubKeyDomain", "warnPhishing",
		"Use SPFM", "APEXCNAME", "hostRequired", "pointsTo is required", "priority is required", "is not one this package expands",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestParseTemplateRefusesWhatItDoesNotUnderstand(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"unknown key":   `{"providerId":"a.b","serviceId":"c","recods":[]}`,
		"not json":      `<xml/>`,
		"trailing data": `{"providerId":"a.b"} {}`,
		"huge":          `{"description":"` + strings.Repeat("a", 2<<20) + `"}`,
	} {
		if _, err := domainconnect.ParseTemplate(strings.NewReader(input)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNumbersMayBeWrittenAsStrings(t *testing.T) {
	t.Parallel()
	tpl, err := domainconnect.ParseTemplate(strings.NewReader(`{"providerId":"a.b","providerName":"A","serviceId":"c","serviceName":"C","syncPubKeyDomain":"a.b",
		"records":[{"type":"MX","host":"m","pointsTo":"x.b","priority":"5","ttl":"%ttl%"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	records, err := tpl.Expand("a.b", "", map[string]string{"ttl": "600"})
	if err != nil || records[0].Priority != 5 || records[0].TTL != 600 {
		t.Errorf("records = %+v, %v", records, err)
	}
}

func FuzzParseTemplate(f *testing.F) {
	seed, _ := os.ReadFile("testdata/example.sending.json")
	f.Add(string(seed))
	f.Add(`{}`)
	f.Add(`{"records":[{"type":"MX","ttl":null,"priority":[1]}]}`)
	f.Fuzz(func(t *testing.T, input string) {
		tpl, err := domainconnect.ParseTemplate(strings.NewReader(input))
		if err != nil {
			return
		}
		_ = tpl.Validate()
		_ = tpl.Variables()
		_, _ = tpl.Expand("example.com", "send", map[string]string{"dkim": "x"})
	})
}

func BenchmarkExpand(b *testing.B) {
	f, _ := os.Open("testdata/example.sending.json")
	tpl, _ := domainconnect.ParseTemplate(f)
	f.Close()
	vars := map[string]string{"dkim": strings.Repeat("A", 392)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := tpl.Expand("example.com", "send", vars); err != nil {
			b.Fatal(err)
		}
	}
}
