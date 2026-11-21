package dns

import (
	"context"
	"errors"
)

// Outcome is what happened to one record when a plan was applied.
type Outcome string

// The outcomes.
const (
	OutcomeCreated  Outcome = "created"
	OutcomeUpdated  Outcome = "updated"
	OutcomeExists   Outcome = "exists"
	OutcomeConflict Outcome = "conflict"
	OutcomeFailed   Outcome = "failed"
)

// Result is the outcome of one item.
type Result struct {
	Item    Item
	Outcome Outcome
	// Record is the record as the provider holds it after a create or an
	// update, or the one that was already there on Exists.
	Record Record
	// Error is why an item failed. It carries the provider's message and never
	// a credential.
	Error string

	err error
}

// Report is the result of applying a plan, one entry per item and in the same
// order.
type Report struct {
	Zone    Zone
	Results []Result
}

// Succeeded reports whether every record is now in place: created, updated or
// already there. A conflict or a failure is not.
func (r Report) Succeeded() bool {
	for _, result := range r.Results {
		switch result.Outcome {
		case OutcomeCreated, OutcomeUpdated, OutcomeExists:
		default:
			return false
		}
	}
	return true
}

// Count answers how many results have the outcome.
func (r Report) Count(outcome Outcome) int {
	n := 0
	for _, result := range r.Results {
		if result.Outcome == outcome {
			n++
		}
	}
	return n
}

// PlanChangedError is ErrPlanChanged with the plan the zone calls for now, so
// the person can be shown it and confirm again.
type PlanChangedError struct{ Fresh Plan }

// Error implements error.
func (e *PlanChangedError) Error() string { return ErrPlanChanged.Error() }

// Unwrap lets errors.Is find ErrPlanChanged.
func (e *PlanChangedError) Unwrap() error { return ErrPlanChanged }

// Apply carries out a plan the person confirmed.
//
// It plans again first, because the zone may have changed since the person
// looked: when the fresh plan is not the confirmed one, nothing is written and
// the error is a *PlanChangedError carrying the new plan. Otherwise it creates
// and updates exactly what the plan says, leaves Exists and Conflict items
// alone and records each outcome.
//
// An error from the provider on one item is recorded on that item and the next
// one is tried, except when the credential is refused, forbidden or rate
// limited: that stops the run and is returned with the report so far.
func Apply(ctx context.Context, provider Provider, confirmed Plan) (Report, error) {
	fresh, err := NewPlan(ctx, provider, confirmed.Zone, confirmed.Wants...)
	if err != nil {
		return Report{Zone: confirmed.Zone}, err
	}
	if fresh.Fingerprint() != confirmed.Fingerprint() {
		return Report{Zone: confirmed.Zone}, &PlanChangedError{Fresh: fresh}
	}

	report := Report{Zone: fresh.Zone}
	for _, item := range fresh.Items {
		result := Result{Item: item}
		switch item.Action {
		case ActionExists:
			result.Outcome, result.Record = OutcomeExists, item.Current[0]
		case ActionConflict:
			result.Outcome = OutcomeConflict
		case ActionCreate:
			result = create(ctx, provider, fresh.Zone, item)
		case ActionUpdate:
			result = update(ctx, provider, fresh.Zone, item)
		}
		report.Results = append(report.Results, result)
		if fatal(result) {
			for _, rest := range fresh.Items[len(report.Results):] {
				report.Results = append(report.Results, Result{Item: rest, Outcome: OutcomeFailed, Error: "not attempted: the run stopped"})
			}
			return report, result.err
		}
	}
	return report, nil
}

// fatal reports whether a failed item ends the run.
func fatal(result Result) bool {
	return result.Outcome == OutcomeFailed && result.err != nil &&
		(errors.Is(result.err, ErrUnauthorized) || errors.Is(result.err, ErrForbidden) || errors.Is(result.err, ErrRateLimited))
}

func create(ctx context.Context, provider Provider, zone Zone, item Item) Result {
	record, err := provider.Create(ctx, zone, item.Want)
	if err == nil {
		return Result{Item: item, Outcome: OutcomeCreated, Record: record}
	}
	if errors.Is(err, ErrRecordExists) {
		// Somebody (or an earlier, interrupted run) wrote it between the plan
		// and the write. If it is the wanted record the outcome is the same as
		// if it had been there.
		if current, lookup := provider.Records(ctx, zone, item.Want.Name); lookup == nil {
			for _, have := range current {
				have.Content = NormalizeContent(have.Type, have.Content)
				if equal(item.Want, have) {
					return Result{Item: item, Outcome: OutcomeExists, Record: have}
				}
			}
		}
	}
	return failed(item, err)
}

func update(ctx context.Context, provider Provider, zone Zone, item Item) Result {
	target := item.Current[0]
	// The one thing an update may never do is reach a record that is not at the
	// name that was asked for.
	if canonicalName(target.Name) != item.Want.Name {
		return failed(item, errors.New("dns: refused to change a record at another name"))
	}
	record, err := provider.Update(ctx, zone, target.ID, item.Want)
	if err != nil {
		return failed(item, err)
	}
	return Result{Item: item, Outcome: OutcomeUpdated, Record: record}
}

func failed(item Item, err error) Result {
	return Result{Item: item, Outcome: OutcomeFailed, Error: err.Error(), err: err}
}
