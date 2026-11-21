package dns_test

import (
	"testing"

	dns "github.com/hyz-is/arandu-dns"
)

func TestNormalizeContent(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		kind dns.RecordType
		in   string
		want string
	}{
		{dns.TypeTXT, `"v=spf1 -all"`, "v=spf1 -all"},
		{dns.TypeTXT, `"abc" "def"`, "abcdef"},
		{dns.TypeTXT, `"say \"hi\""`, `say "hi"`},
		{dns.TypeTXT, "plain text", "plain text"},
		{dns.TypeTXT, `"unterminated`, `"unterminated`},
		{dns.TypeMX, "MX.Example.NET.", "mx.example.net"},
		{dns.TypeCNAME, "Target.Example.Net.", "target.example.net"},
		{dns.TypeAAAA, "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"},
		{dns.TypeA, " 192.0.2.1 ", "192.0.2.1"},
	} {
		if got := dns.NormalizeContent(c.kind, c.in); got != c.want {
			t.Errorf("NormalizeContent(%s, %q) = %q, want %q", c.kind, c.in, got, c.want)
		}
	}
}

func FuzzNormalizeContent(f *testing.F) {
	for _, seed := range []string{`"a" "b"`, `"`, `"\`, `""`, "v=spf1 -all", `"a"b"`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		once := dns.NormalizeContent(dns.TypeTXT, in)
		_ = dns.NormalizeContent(dns.TypeMX, in)
		_ = dns.NormalizeContent(dns.TypeAAAA, in)
		if len(once) > len(in) {
			t.Errorf("normalizing grew %q into %q", in, once)
		}
	})
}

func BenchmarkPlan(b *testing.B) {
	f := newBenchZone()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dns.NewPlan(b.Context(), f.provider, f.zone, f.wants...); err != nil {
			b.Fatal(err)
		}
	}
}
