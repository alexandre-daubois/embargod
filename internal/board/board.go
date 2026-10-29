// Package board keeps a private GitHub project in sync with the triaged advisories, one draft item each.
package board

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
)

const (
	LookFirst    = "Look first"
	WhenPossible = "When possible"
	// AnalysisPending marks an advisory whose analysis started, AnalysisRetrying and AnalysisFailed one whose
	// analysis failed, with and without another attempt to come. The draft body says more.
	AnalysisPending  = "Analysis pending"
	AnalysisRetrying = "Analysis failed, retrying"
	AnalysisFailed   = "Analysis failed"
	Duplicate        = "Duplicate"
)

const (
	fieldGHSA        = "GHSA"
	fieldDuplicateOf = "Duplicate of"
	fieldDuplicates  = "Duplicates"
	fieldReported    = "Reported"
	fieldPriority    = "Priority"
	fieldSeverity    = "Severity"
	fieldState       = "State"
	fieldExcluded    = "Policy exclusion"
	fieldLocated     = "Located"
	fieldComponent   = "Component"
	fieldGroup       = "Original report"
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
	{fieldPriority, "single_select", []string{LookFirst, WhenPossible, Duplicate, AnalysisFailed, AnalysisRetrying, AnalysisPending}},
	{fieldSeverity, "single_select", []string{"Critical", "High", "Medium", "Low"}},
	{fieldState, "single_select", []string{"triage", "draft", "published", "closed", "withdrawn"}},
	{fieldExcluded, "single_select", []string{"Yes", "No"}},
	{fieldLocated, "single_select", []string{"Yes", "No"}},
	{fieldComponent, "text", nil},
	{fieldGroup, "text", nil},
}

type GitHub interface {
	GetProject(ctx context.Context, org string, number int) (github.Project, error)
	ListProjectFields(ctx context.Context, org string, number int) ([]github.ProjectField, error)
	ListProjectItems(ctx context.Context, org string, number int, fields []int64) ([]github.ProjectItem, error)
	CreateDraft(ctx context.Context, org string, number int, title, body string) (github.ProjectItem, error)
	UpdateDraft(ctx context.Context, draft, body string) error
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
	id                              int64
	ghsa, draft, duplicateOf, state string
	priority, group                 string
	duplicates                      int
	// triage is nil for an item without one, whose priority is a status Sync leaves alone.
	triage *Triage
}

// Triage is what the board keeps of a triage, enough to rank it again when the rule changes.
type Triage struct {
	Severity, DuplicateOf string
	Excluded, Located     bool
	// Component is the directory of the faulty statement, two levels deep, empty when it was not located.
	Component string
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

	items, err := gh.ListProjectItems(ctx, org, number, []int64{b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldDuplicates], b.ids[fieldState], b.ids[fieldPriority], b.ids[fieldSeverity], b.ids[fieldExcluded], b.ids[fieldLocated], b.ids[fieldGroup]})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var ghsa, severity, excluded, located string
		entry := &item{id: it.ID, draft: it.Content.NodeID}
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
			case b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldState], b.ids[fieldPriority], b.ids[fieldSeverity], b.ids[fieldExcluded], b.ids[fieldLocated], b.ids[fieldGroup]:
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
			case b.ids[fieldPriority]:
				entry.priority = text.Name.Raw
			case b.ids[fieldSeverity]:
				severity = strings.ToLower(text.Name.Raw)
			case b.ids[fieldExcluded]:
				excluded = text.Name.Raw
			case b.ids[fieldLocated]:
				located = text.Name.Raw
			case b.ids[fieldGroup]:
				entry.group = text.Raw
			}
		}
		if excluded != "" && located != "" {
			entry.triage = &Triage{Severity: severity, DuplicateOf: entry.duplicateOf, Excluded: excluded == "Yes", Located: located == "Yes"}
		}
		if ghsa != "" {
			entry.ghsa = ghsa
			b.items[strings.ToLower(ghsa)] = entry
		}
	}

	return b, nil
}

// Has says whether ghsa has an item.
func (b *Board) Has(ghsa string) bool {
	return b.items[strings.ToLower(ghsa)] != nil
}

// TriageOf keeps what the board needs of r, with the oldest high-confidence exact duplicate the comment shows.
func TriageOf(r report.Report) Triage {
	t := Triage{Severity: r.Severity, Excluded: len(r.PolicyExclusions) > 0, Located: r.Located}
	t.Component = r.Component
	if dir := path.Dir(r.Location.Path); t.Component == "" && r.Located && dir != "." {
		parts := strings.Split(dir, "/")
		t.Component = strings.Join(parts[:min(len(parts), 2)], "/")
	}
	var oldest *report.Duplicate
	for i, d := range r.Duplicates {
		if d.Exact && d.Confidence == "high" && (d.Published || d.Confirmed) && d.CreatedAt.Before(r.CreatedAt) && (oldest == nil || d.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = &r.Duplicates[i]
		}
	}
	if oldest != nil {
		t.DuplicateOf = oldest.GHSAID
	}

	return t
}

// Priority ranks a triage. A report goes behind its oldest duplicate, the others are looked at first only when
// severe, with the faulty statement located and no policy exclusion. Reports cite their own proof-of-concept
// files, so a cited file missing from the repository says nothing.
func (t Triage) Priority() string {
	switch {
	case t.DuplicateOf != "":
		return Duplicate
	case t.Severity != "critical" && t.Severity != "high" || t.Excluded || !t.Located:
		return WhenPossible
	default:
		return LookFirst
	}
}

// Put creates the item of a, or updates the one it has. A nil t sets priority as a status and clears the
// fields of a triage. The draft body holds the advisory link, then comment when there is one. The title is
// only set on creation.
func (b *Board) Put(ctx context.Context, a github.Advisory, priority string, t *Triage, comment string) error {
	key := strings.ToLower(a.GHSAID)
	body := a.HTMLURL
	if comment != "" {
		body += "\n\n" + comment
	}
	it := b.items[key]
	switch {
	case it == nil:
		draft, err := b.gh.CreateDraft(ctx, b.org, b.number, a.Summary, body)
		if err != nil {
			return err
		}
		it = &item{id: draft.ID, draft: draft.Content.NodeID, ghsa: a.GHSAID}
		b.items[key] = it
	case comment != "":
		if err := b.gh.UpdateDraft(ctx, it.draft, body); err != nil {
			return err
		}
	}
	var kept Triage
	if t != nil {
		kept = *t
	}
	values := []github.FieldValue{
		{ID: b.ids[fieldGHSA], Value: a.GHSAID},
		{ID: b.ids[fieldReported], Value: a.CreatedAt.UTC().Format(time.DateOnly)},
		b.option(fieldState, a.State),
		b.option(fieldPriority, priority),
		b.option(fieldSeverity, capitalize(kept.Severity)),
		{ID: b.ids[fieldDuplicateOf], Value: nil},
		b.option(fieldExcluded, ""),
		b.option(fieldLocated, ""),
		{ID: b.ids[fieldComponent], Value: text(kept.Component)},
	}
	values[5].Value = text(kept.DuplicateOf)
	if t != nil {
		values[6], values[7] = b.option(fieldExcluded, yes(t.Excluded)), b.option(fieldLocated, yes(t.Located))
	}
	if err := b.gh.UpdateProjectItem(ctx, b.org, b.number, it.id, values); err != nil {
		return err
	}
	it.duplicateOf, it.state, it.priority, it.triage = kept.DuplicateOf, a.State, priority, t

	return nil
}

// text sets a text field, or clears it when s is empty.
func text(s string) any {
	if s == "" {
		return nil
	}

	return s
}

func yes(v bool) string {
	if v {
		return "Yes"
	}

	return "No"
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}

	return strings.ToUpper(s[:1]) + s[1:]
}

// oldest follows the Duplicate of chain from ghsa, since the original of a report can itself name an older one.
func (b *Board) oldest(ghsa string) string {
	seen := map[string]bool{}
	for {
		it := b.items[strings.ToLower(ghsa)]
		if it == nil || it.duplicateOf == "" || seen[strings.ToLower(ghsa)] {
			return ghsa
		}
		seen[strings.ToLower(ghsa)] = true
		ghsa = it.duplicateOf
	}
}

// option sets a single select field, or clears it when the value has no option.
func (b *Board) option(field, value string) github.FieldValue {
	v := github.FieldValue{ID: b.ids[field]}
	if id := b.options[field][value]; id != "" {
		v.Value = id
	}

	return v
}

// Sync mirrors the state of every advisory on its item, counts the duplicates of each report, gives every
// report of a duplicate group the identifier of its oldest one and ranks every triage again, so a new priority
// rule reaches the board without a model run. It only writes the items that changed.
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
		if it.triage != nil && it.triage.Priority() != it.priority {
			it.priority = it.triage.Priority()
			values = append(values, b.option(fieldPriority, it.priority))
		}
		if counts[ghsa] != it.duplicates {
			it.duplicates = counts[ghsa]
			values = append(values, github.FieldValue{ID: b.ids[fieldDuplicates], Value: it.duplicates})
		}
		group := ""
		switch {
		case it.duplicateOf != "":
			group = b.oldest(it.duplicateOf)
		case counts[ghsa] > 0:
			group = it.ghsa
		}
		if group != it.group {
			it.group = group
			values = append(values, github.FieldValue{ID: b.ids[fieldGroup], Value: text(group)})
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
