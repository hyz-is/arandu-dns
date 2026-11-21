package dns

import (
	"context"
	"strings"
)

// Neighbours lists the records of the zone, at scope and below it, that look
// like another service's way of sending mail for the same domain and that the
// plan leaves alone: an MX or an SPF record at the scope itself, a DKIM key at
// any selector, and the MX, SPF and well-known return-path aliases directly
// under it. Records at the names the plan decided about are not listed: the
// plan already says what happens to them.
//
// It is for showing the person what else is there. It reads, writes nothing
// and decides nothing. A provider that does not implement Lister answers none.
// The match is a heuristic by name and type, never by provider: a record it
// does not recognise is not listed, and a listed one is not necessarily
// another service's.
func Neighbours(ctx context.Context, provider Provider, plan Plan, scope string) ([]Record, error) {
	lister, ok := provider.(Lister)
	if !ok {
		return nil, nil
	}
	scope = canonicalName(scope)
	found, err := lister.RecordsUnder(ctx, plan.Zone, scope)
	if err != nil {
		return nil, err
	}
	planned := map[string]bool{}
	for _, item := range plan.Items {
		planned[item.Want.Name] = true
	}
	var out []Record
	for _, record := range found {
		record.Name = canonicalName(record.Name)
		record.Content = NormalizeContent(record.Type, record.Content)
		if planned[record.Name] || !looksLikeMail(plan.Zone, scope, record) {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

// returnLabels are the names a sending service commonly gives the alias or the
// host of its bounce address.
var returnLabels = map[string]bool{
	"send": true, "rsend": true, "bounce": true, "bounces": true, "mail": true, "mailfrom": true,
	"em": true, "smtp": true, "return": true, "bnc": true, "mg": true, "email": true, "mta": true,
}

// looksLikeMail reports whether a record at or under the scope belongs to the
// mail of the domain, by where it sits and what it is.
func looksLikeMail(zone Zone, scope string, record Record) bool {
	if record.Name != scope && !strings.HasSuffix(record.Name, "."+scope) {
		return false
	}
	relative := strings.TrimSuffix(strings.TrimSuffix(record.Name, scope), ".")
	atZoneApex := scope == canonicalName(zone.Name)
	switch {
	case relative == "":
		// The mail of the domain itself. At a zone's apex that is the owner's
		// own mail, not another service.
		return !atZoneApex && (record.Type == TypeMX || (record.Type == TypeTXT && txtFamily(record.Name, record.Content) == familySPF))
	case strings.HasSuffix(relative, "._domainkey") || strings.Contains(relative, "._domainkey."):
		return record.Type == TypeTXT || record.Type == TypeCNAME
	case !strings.Contains(relative, "."):
		switch record.Type {
		case TypeMX:
			return true
		case TypeTXT:
			return txtFamily(record.Name, record.Content) == familySPF
		case TypeCNAME:
			label := strings.TrimRight(relative, "0123456789")
			return returnLabels[relative] || (label != relative && returnLabels[label])
		}
	}
	return false
}
