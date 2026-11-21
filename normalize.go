package dns

import (
	"fmt"
	"net/netip"
	"strings"
)

// canonicalName lower-cases a name and drops the trailing dot.
func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// fullName resolves a Want's name against its zone.
func fullName(zone Zone, name string) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "" || name == "@":
		return canonicalName(zone.Name)
	case strings.HasSuffix(name, "."):
		return canonicalName(name)
	}
	return canonicalName(name) + "." + canonicalName(zone.Name)
}

// checkText refuses a value that cannot be written to a zone file or a header
// safely: a control character in a name or in content.
func checkText(what, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s has a control character", ErrInvalid, what)
		}
	}
	return nil
}

// NormalizeContent puts a record's data in the form a comparison reads: a TXT
// record unquoted with its chunks joined, a host lower case without a trailing
// dot, an address in its canonical spelling.
func NormalizeContent(kind RecordType, content string) string {
	content = strings.TrimSpace(content)
	switch kind {
	case TypeTXT:
		return joinTXT(content)
	case TypeMX, TypeCNAME:
		return canonicalName(content)
	case TypeA, TypeAAAA:
		if addr, err := netip.ParseAddr(content); err == nil {
			return addr.String()
		}
	}
	return content
}

// joinTXT reads the presentation form of a TXT record: one string, or several
// quoted strings separated by spaces, which are joined. Text that is not
// quoted is returned as it is.
func joinTXT(content string) string {
	if !strings.HasPrefix(content, `"`) {
		return content
	}
	var out strings.Builder
	rest := content
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return out.String()
		}
		if rest[0] != '"' {
			// Not a sequence of quoted strings: keep what was given.
			return content
		}
		rest = rest[1:]
		for {
			if rest == "" {
				return content
			}
			c := rest[0]
			if c == '\\' && len(rest) > 1 {
				out.WriteByte(rest[1])
				rest = rest[2:]
				continue
			}
			rest = rest[1:]
			if c == '"' {
				break
			}
			out.WriteByte(c)
		}
	}
}

// The families of TXT record that may exist only once at a name.
const (
	familyNone  = ""
	familySPF   = "spf"
	familyDMARC = "dmarc"
	familyDKIM  = "dkim"
)

// txtFamily says whether a TXT record is an SPF policy, a DMARC policy or a
// DKIM key. Those are the records where two at one name is a fault, and where a
// different value is the same record changed rather than another record.
func txtFamily(name, content string) string {
	lower := strings.ToLower(strings.TrimSpace(content))
	switch {
	case lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 "):
		return familySPF
	case strings.HasPrefix(lower, "v=dmarc1"):
		return familyDMARC
	case strings.HasPrefix(lower, "v=dkim1"):
		return familyDKIM
	case strings.Contains(name, "._domainkey.") && hasTag(lower, "p"):
		return familyDKIM
	}
	return familyNone
}

// tags reads a "k=v; k=v" record into a map of lower-case keys.
func tags(content string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(content, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, seen := out[key]; !seen {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func hasTag(content, key string) bool {
	_, ok := tags(content)[key]
	return ok
}

// sameContent reports whether two records of one type and name say the same
// thing. A DKIM key is the same when its p tag and its key type are; SPF and
// DMARC are the same ignoring case and spacing; everything else is the
// normalized content.
func sameContent(kind RecordType, name, a, b string) bool {
	a, b = NormalizeContent(kind, a), NormalizeContent(kind, b)
	if a == b {
		return true
	}
	if kind != TypeTXT {
		return false
	}
	fa, fb := txtFamily(name, a), txtFamily(name, b)
	if fa != fb {
		return false
	}
	switch fa {
	case familyDKIM:
		ta, tb := tags(a), tags(b)
		keyType := func(t map[string]string) string {
			if k := strings.ToLower(t["k"]); k != "" {
				return k
			}
			return "rsa"
		}
		strip := func(s string) string { return strings.Join(strings.Fields(s), "") }
		return strip(ta["p"]) != "" && strip(ta["p"]) == strip(tb["p"]) && keyType(ta) == keyType(tb)
	case familySPF, familyDMARC:
		squash := func(s string) string {
			s = strings.ToLower(strings.Join(strings.Fields(s), " "))
			return strings.TrimSuffix(strings.ReplaceAll(s, "; ", ";"), ";")
		}
		return squash(a) == squash(b)
	}
	return false
}
