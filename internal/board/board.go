// Package board keeps a private GitHub project in sync with the triaged advisories, one draft item each.
package board

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
)

const (
	LookFirst    = "Look first"
	Later        = "Later"
	ManualTriage = "Needs manual triage"
	Duplicate    = "Duplicate"
)

const (
	fieldGHSA        = "GHSA"
	fieldDuplicateOf = "Duplicate of"
	fieldDuplicates  = "Duplicates"
	fieldReported    = "Reported"
	fieldPriority    = "Priority"
	fieldSeverity    = "Severity"
	fieldState       = "State"
)

// layout lists the fields the project must have, created by hand as docs/setup.md describes.
var layout = []struct {
	name, dataType string
	options        []string
}{
	{fieldGHSA, "text", nil},
	{fieldDuplicateOf, "text", nil},
	{fieldDuplicates, "number", nil},
	{fieldReported, "date", nil},
	{fieldPriority, "single_select", []string{LookFirst, Later, ManualTriage, Duplicate}},
	{fieldSeverity, "single_select", []string{"Critical", "High", "Medium", "Low"}},
	{fieldState, "single_select", []string{"triage", "draft", "published", "closed", "withdrawn"}},
}

type GitHub interface {
	GetProject(ctx context.Context, org string, number int) (github.Project, error)
	ListProjectFields(ctx context.Context, org string, number int) ([]github.ProjectField, error)
	ListProjectItems(ctx context.Context, org string, number int, fields []int64) ([]github.ProjectItem, error)
	CreateDraft(ctx context.Context, org string, number int, title, body string) (int64, error)
	UpdateProjectItem(ctx context.Context, org string, number int, item int64, fields []github.FieldValue) error
}

type Board struct {
	gh      GitHub
	org     string
	number  int
	ids     map[string]int64
	options map[string]map[string]string
	// items is keyed by lowercase GHSA identifier, items without one were added by hand and stay untouched.
	items map[string]*item
}

type item struct {
	id                 int64
	duplicateOf, state string
	duplicates         int
}

// Open loads the fields and items of project, given as "org/number".
func Open(ctx context.Context, gh GitHub, project string) (*Board, error) {
	org, n, _ := strings.Cut(project, "/")
	number, err := strconv.Atoi(n)
	if org == "" || err != nil {
		return nil, errors.New(`the project must be given as "org/number"`)
	}
	p, err := gh.GetProject(ctx, org, number)
	if err != nil {
		return nil, err
	}
	// The items name advisories under embargo, with their title.
	if p.Public {
		return nil, errors.New("the project must be private")
	}
	b := &Board{gh: gh, org: org, number: number, ids: map[string]int64{}, options: map[string]map[string]string{}, items: map[string]*item{}}
	fields, err := gh.ListProjectFields(ctx, org, number)
	if err != nil {
		return nil, err
	}
	for _, want := range layout {
		i := slices.IndexFunc(fields, func(f github.ProjectField) bool { return f.Name == want.name && f.DataType == want.dataType })
		if i < 0 {
			return nil, fmt.Errorf("the project has no %s field %q", want.dataType, want.name)
		}
		b.ids[want.name] = fields[i].ID
		if want.options == nil {
			continue
		}
		b.options[want.name] = map[string]string{}
		for _, o := range fields[i].Options {
			b.options[want.name][o.Name.Raw] = o.ID
		}
		for _, o := range want.options {
			if b.options[want.name][o] == "" {
				return nil, fmt.Errorf("the %q field has no %q option", want.name, o)
			}
		}
	}

	items, err := gh.ListProjectItems(ctx, org, number, []int64{b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldDuplicates], b.ids[fieldState]})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var ghsa string
		entry := &item{id: it.ID}
		for _, f := range it.Fields {
			var text struct {
				Raw  string `json:"raw"`
				Name struct {
					Raw string `json:"raw"`
				} `json:"name"`
			}
			var count float64
			var err error
			switch f.ID {
			case b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldState]:
				err = json.Unmarshal(f.Value, &text)
			case b.ids[fieldDuplicates]:
				err = json.Unmarshal(f.Value, &count)
			}
			// An unread GHSA would make the item look added by hand, and its advisory triaged again on every run.
			if err != nil {
				return nil, fmt.Errorf("the project item %d has a value in an unexpected format", it.ID)
			}
			switch f.ID {
			case b.ids[fieldGHSA]:
				ghsa = text.Raw
			case b.ids[fieldDuplicateOf]:
				entry.duplicateOf = text.Raw
			case b.ids[fieldState]:
				entry.state = text.Name.Raw
			case b.ids[fieldDuplicates]:
				entry.duplicates = int(count)
			}
		}
		if ghsa != "" {
			b.items[strings.ToLower(ghsa)] = entry
		}
	}

	return b, nil
}

// Has says whether ghsa has an item.
func (b *Board) Has(ghsa string) bool {
	return b.items[strings.ToLower(ghsa)] != nil
}

// Prioritize ranks a triaged report. A report goes behind the oldest high-confidence exact duplicate the comment shows, the
// others are looked at first only when severe, with the faulty statement located and no policy exclusion.
// Reports cite their own proof-of-concept files, so a cited file missing from the repository says nothing.
func Prioritize(r report.Report) (priority, duplicateOf string) {
	var oldest *report.Duplicate
	for i, d := range r.Duplicates {
		if d.Exact && d.Confidence == "high" && (d.Published || d.Confirmed) && d.CreatedAt.Before(r.CreatedAt) && (oldest == nil || d.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = &r.Duplicates[i]
		}
	}
	if oldest != nil {
		return Duplicate, oldest.GHSAID
	}
	if r.Severity != "critical" && r.Severity != "high" || len(r.PolicyExclusions) > 0 || !r.Located {
		return Later, ""
	}

	return LookFirst, ""
}

// Put creates the item of a, or updates the one it has. The title and body are only set on creation.
func (b *Board) Put(ctx context.Context, a github.Advisory, priority, severity, duplicateOf string) error {
	key := strings.ToLower(a.GHSAID)
	it := b.items[key]
	if it == nil {
		id, err := b.gh.CreateDraft(ctx, b.org, b.number, a.Summary, a.HTMLURL)
		if err != nil {
			return err
		}
		it = &item{id: id}
		b.items[key] = it
	}
	values := []github.FieldValue{
		{ID: b.ids[fieldGHSA], Value: a.GHSAID},
		{ID: b.ids[fieldReported], Value: a.CreatedAt.UTC().Format(time.DateOnly)},
		b.option(fieldState, a.State),
		b.option(fieldPriority, priority),
		b.option(fieldSeverity, capitalize(severity)),
		{ID: b.ids[fieldDuplicateOf], Value: nil},
	}
	if duplicateOf != "" {
		values[len(values)-1].Value = duplicateOf
	}
	if err := b.gh.UpdateProjectItem(ctx, b.org, b.number, it.id, values); err != nil {
		return err
	}
	it.duplicateOf, it.state = duplicateOf, a.State

	return nil
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}

	return strings.ToUpper(s[:1]) + s[1:]
}

// option sets a single select field, or clears it when the value has no option.
func (b *Board) option(field, value string) github.FieldValue {
	v := github.FieldValue{ID: b.ids[field]}
	if id := b.options[field][value]; id != "" {
		v.Value = id
	}

	return v
}

// Sync mirrors the state of every advisory on its item and counts the duplicates of each report. It only
// writes the items that changed.
func (b *Board) Sync(ctx context.Context, advisories []github.Advisory) error {
	states := map[string]string{}
	for _, a := range advisories {
		states[strings.ToLower(a.GHSAID)] = a.State
	}
	counts := map[string]int{}
	for _, it := range b.items {
		if it.duplicateOf != "" {
			counts[strings.ToLower(it.duplicateOf)]++
		}
	}

	var errs []error
	for ghsa, it := range b.items {
		var values []github.FieldValue
		if state, ok := states[ghsa]; ok && state != it.state {
			values = append(values, b.option(fieldState, state))
			it.state = state
		}
		if counts[ghsa] != it.duplicates {
			it.duplicates = counts[ghsa]
			values = append(values, github.FieldValue{ID: b.ids[fieldDuplicates], Value: it.duplicates})
		}
		if len(values) == 0 {
			continue
		}
		if err := b.gh.UpdateProjectItem(ctx, b.org, b.number, it.id, values); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
