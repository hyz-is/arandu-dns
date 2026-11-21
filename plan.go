package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Action is what a plan would do about one wanted record.
type Action string

// The actions.
const (
	// ActionCreate: nothing is there, the record would be added.
	ActionCreate Action = "create"
	// ActionUpdate: the same record is there with another value, and would be
	// changed to the wanted one.
	ActionUpdate Action = "update"
	// ActionReplace: records of another kind or with other data hold the name,
	// and would be removed so that the wanted record takes their place. Only a
	// Want with Takeover gets this; Item.Current lists what would be removed.
	ActionReplace Action = "replace"
	// ActionExists: the record is already there as wanted.
	ActionExists Action = "exists"
	// ActionConflict: something is there that the plan will not touch. The
	// person decides.
	ActionConflict Action = "conflict"
)

// The reasons of a Conflict. A caller translates by code; Reason carries the
// English sentence.
const (
	// ConflictCNAME: a CNAME cannot share its name with another record.
	ConflictCNAME = "cname_exclusive"
	// ConflictOtherRecords: the name holds records of this type with other
	// data, and adding or replacing would change what the name does.
	ConflictOtherRecords = "other_records"
	// ConflictApex: the record is an apex MX, SPF or DMARC that exists with
	// another value, and the request did not say Replace.
	ConflictApex = "apex_protected"
	// ConflictAmbiguous: more than one existing record could be the one to
	// change.
	ConflictAmbiguous = "ambiguous"
)

// Item is one wanted record and what the plan decided about it.
type Item struct {
	// Want is the record as it would be written, with its full name.
	Want   Record
	Action Action
	// Current are the existing records that matter: the one that is already
	// right (Exists), the one that would change (Update), the ones that would
	// be removed (Replace) or the ones in the way (Conflict). It is empty on a
	// Create.
	Current []Record
	// Code and Reason say why an item is a Conflict.
	Code   string
	Reason string
	// Replace is whether the request asked to change a protected record.
	Replace bool
}

// Plan is what applying a set of wanted records would do to a zone, decided
// against what the zone holds now.
type Plan struct {
	Zone  Zone
	Wants []Want
	Items []Item
}

// Count answers how many items have the action.
func (p Plan) Count(action Action) int {
	n := 0
	for _, item := range p.Items {
		if item.Action == action {
			n++
		}
	}
	return n
}

// HasConflicts reports whether any item is a Conflict.
func (p Plan) HasConflicts() bool { return p.Count(ActionConflict) > 0 }

// Pending reports whether applying the plan would write anything.
func (p Plan) Pending() bool {
	return p.Count(ActionCreate)+p.Count(ActionUpdate)+p.Count(ActionReplace) > 0
}

// Fingerprint identifies what the plan decides, so that a plan the person
// confirmed can be compared with the one made at the moment of applying.
func (p Plan) Fingerprint() string {
	sum := sha256.New()
	for _, item := range p.Items {
		ids := make([]string, 0, len(item.Current))
		for _, c := range item.Current {
			ids = append(ids, c.ID)
		}
		sort.Strings(ids)
		fmt.Fprintf(sum, "%s|%s|%s|%s|%d|%s\n", item.Action, item.Want.Type, item.Want.Name,
			NormalizeContent(item.Want.Type, item.Want.Content), item.Want.Priority, strings.Join(ids, ","))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// NewPlan reads the records the provider holds at the wanted names, and decides
// what to do about each wanted record. It writes nothing.
//
// It answers ErrInvalid, wrapped, for a Want that cannot be applied: a name
// outside the zone, empty content, a control character.
func NewPlan(ctx context.Context, provider Provider, zone Zone, wants ...Want) (Plan, error) {
	resolved := make([]Record, len(wants))
	seen := map[string]bool{}
	var names []string
	for i, want := range wants {
		record, err := resolve(zone, want)
		if err != nil {
			return Plan{}, err
		}
		resolved[i] = record
		if !seen[record.Name] {
			seen[record.Name] = true
			names = append(names, record.Name)
		}
	}

	existing, err := provider.Records(ctx, zone, names...)
	if err != nil {
		return Plan{}, err
	}
	// Only the names that were asked for are looked at, whatever the provider
	// answered with.
	byName := map[string][]Record{}
	for _, record := range existing {
		record.Name = canonicalName(record.Name)
		if seen[record.Name] {
			record.Content = NormalizeContent(record.Type, record.Content)
			byName[record.Name] = append(byName[record.Name], record)
		}
	}

	plan := Plan{Zone: zone, Wants: append([]Want(nil), wants...)}
	for i, want := range wants {
		plan.Items = append(plan.Items, decide(zone, resolved[i], want.Replace, want.Takeover, byName[resolved[i].Name]))
	}
	return plan, nil
}

// resolve checks a Want and gives the record it asks for.
func resolve(zone Zone, want Want) (Record, error) {
	if want.Type == "" {
		return Record{}, fmt.Errorf("%w: a record has no type", ErrInvalid)
	}
	if err := checkText("the name", want.Name); err != nil {
		return Record{}, err
	}
	if err := checkText("the content", want.Content); err != nil {
		return Record{}, err
	}
	if strings.TrimSpace(want.Content) == "" {
		return Record{}, fmt.Errorf("%w: %s %q has no content", ErrInvalid, want.Type, want.Name)
	}
	name := fullName(zone, want.Name)
	zoneName := canonicalName(zone.Name)
	if name != zoneName && !strings.HasSuffix(name, "."+zoneName) {
		return Record{}, fmt.Errorf("%w: %q is outside the zone %s", ErrInvalid, name, zoneName)
	}
	if want.TTL < 0 {
		return Record{}, fmt.Errorf("%w: %s %q has a negative TTL", ErrInvalid, want.Type, name)
	}
	return Record{
		Type: want.Type, Name: name, Content: NormalizeContent(want.Type, want.Content),
		TTL: want.TTL, Priority: want.Priority, Comment: want.Comment,
	}, nil
}

// equal reports whether an existing record is the wanted one.
func equal(want, have Record) bool {
	if want.Type != have.Type || !sameContent(want.Type, want.Name, want.Content, have.Content) {
		return false
	}
	return want.Type != TypeMX || want.Priority == have.Priority
}

// protected reports whether the wanted record is one of the three that decide
// where a domain's mail goes and who may send it, at the apex of the zone.
func protected(zone Zone, want Record) bool {
	apex := canonicalName(zone.Name)
	switch want.Type {
	case TypeMX:
		return want.Name == apex
	case TypeTXT:
		switch txtFamily(want.Name, want.Content) {
		case familySPF:
			return want.Name == apex
		case familyDMARC:
			return want.Name == "_dmarc."+apex
		}
	}
	return false
}

// decide is the rule of the package: what to do about one wanted record, given
// the records that exist at its name.
func decide(zone Zone, want Record, replace, takeover bool, at []Record) Item {
	item := Item{Want: want, Replace: replace}
	conflict := func(code, reason string, current []Record) Item {
		item.Action, item.Code, item.Reason, item.Current = ActionConflict, code, reason, current
		return item
	}
	// supersede is the answer when the name is the caller's: what is in the way
	// goes, and the wanted record takes its place.
	supersede := func(current []Record) Item {
		item.Action, item.Current = ActionReplace, current
		return item
	}
	guarded := protected(zone, want)

	// Already there as wanted: nothing else at the name matters.
	for _, have := range at {
		if equal(want, have) {
			item.Action, item.Current = ActionExists, []Record{have}
			return item
		}
	}

	// A CNAME owns its name, in both directions.
	var cnames, others []Record
	for _, have := range at {
		if have.Type == TypeCNAME {
			cnames = append(cnames, have)
		} else {
			others = append(others, have)
		}
	}
	if want.Type == TypeCNAME {
		if len(others) > 0 {
			if takeover {
				return supersede(at)
			}
			return conflict(ConflictCNAME, "A CNAME cannot share its name with other records, and this name has some.", others)
		}
		return changeOne(item, cnames, guarded, replace, takeover, conflict)
	}
	if len(cnames) > 0 {
		if takeover {
			return supersede(cnames)
		}
		return conflict(ConflictCNAME, "This name is an alias (CNAME), and an alias cannot hold other records.", cnames)
	}

	var sameType []Record
	for _, have := range at {
		if have.Type == want.Type {
			sameType = append(sameType, have)
		}
	}

	if want.Type == TypeTXT {
		family := txtFamily(want.Name, want.Content)
		if family == familyNone {
			// Plain TXT records coexist.
			item.Action = ActionCreate
			return item
		}
		var inFamily []Record
		for _, have := range sameType {
			if txtFamily(have.Name, have.Content) == family {
				inFamily = append(inFamily, have)
			}
		}
		return changeOne(item, inFamily, guarded, replace, takeover, conflict)
	}

	if len(sameType) == 0 {
		item.Action = ActionCreate
		return item
	}
	// MX, A, AAAA and the rest hold several values, and adding one to a name
	// that has others changes where it points. Changing it is only possible when
	// it is asked for: by Replace on a protected record with exactly one to
	// change, or by Takeover, which makes the name this record's alone.
	if guarded && !replace {
		return conflict(ConflictApex, "The apex already has a record of this kind with another value. Changing it would change how the whole domain works, so it was left alone.", sameType)
	}
	if len(sameType) == 1 && (replace || takeover) {
		item.Action, item.Current = ActionUpdate, sameType
		return item
	}
	if takeover {
		return supersede(sameType)
	}
	return conflict(ConflictOtherRecords, "This name already has records of this type with other data, and they were left alone.", sameType)
}

// changeOne decides among the existing records of one kind at the name that a
// wanted record would replace: none is a create, one is an update, and a
// protected one needs the request to say so. Several are ambiguous, unless the
// name is the caller's: then they are all replaced.
func changeOne(item Item, candidates []Record, guarded, replace, takeover bool, conflict func(string, string, []Record) Item) Item {
	switch {
	case len(candidates) == 0:
		item.Action = ActionCreate
	case len(candidates) > 1 && !takeover:
		return conflict(ConflictAmbiguous, "More than one record could be the one to change, so none was.", candidates)
	case guarded && !replace:
		return conflict(ConflictApex, "The apex already has this record with another value. Changing it would change how the whole domain works, so it was left alone.", candidates)
	case len(candidates) > 1:
		item.Action, item.Current = ActionReplace, candidates
	default:
		item.Action, item.Current = ActionUpdate, candidates
	}
	return item
}
