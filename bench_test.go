package dns_test

import (
	dns "github.com/hyz-is/arandu-dns"
	"github.com/hyz-is/arandu-dns/dnstest"
)

type benchZone struct {
	provider dns.Provider
	zone     dns.Zone
	wants    []dns.Want
}

func newBenchZone() benchZone {
	f := dnstest.New(zone)
	for i := 0; i < 200; i++ {
		f.Seed(zone, dns.Record{Type: dns.TypeTXT, Name: "host" + string(rune('a'+i%26)) + ".example.com", Content: "x"})
	}
	return benchZone{provider: f, zone: zone, wants: wantSet()}
}
