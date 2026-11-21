// Package dnstest is a DNS provider that lives in memory, for the tests of an
// application that uses arandu-dns. It touches no network and keeps a log of
// every call, so a test can prove what a flow did and what it did not.
package dnstest
