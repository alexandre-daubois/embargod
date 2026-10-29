// Package boardtest fakes a GitHub project laid out as docs/setup.md describes.
package boardtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/php/tamis/internal/github"
)

type Project struct {
	Fields []github.ProjectField
	// Items holds the values written on each item, by field ID: an option ID for a single select field.
	Items  map[int64]map[int64]any
	Titles map[int64]string
	Bodies map[int64]string
	// Err fails every write, UpdateErr only the field updates, ListErr every read.
	Err       error
	UpdateErr error
	ListErr   error
	Writes    int
	Public    bool
	next      int64
	// Repos says which repositories exist and whether they are private. Issues holds their issues by number,
	// and issueOf the issue of each item that is one.
	Repos    map[string]bool
	Issues   map[int]*Issue
	IssueErr error
	issueOf  map[int64]int
}

type Issue struct {
	ID                                    int64
	Repo, Title, Body, State, StateReason string
	Parent                                int
}

func New() *Project {
	p := &Project{Items: map[int64]map[int64]any{}, Titles: map[int64]string{}, Bodies: map[int64]string{}, Repos: map[string]bool{"php/php-src-security": true, "php/php-src": false}, Issues: map[int]*Issue{}, issueOf: map[int64]int{}}
	for i, f := range []struct {
		name, dataType string
		options        []string
	}{
		{"Title", "title", nil},
		{"GHSA", "text", nil},
		{"Duplicate of", "text", nil},
		{"Duplicates", "number", nil},
		{"Reported", "date", nil},
		{"Priority", "single_select", []string{"Look first", "When possible", "Duplicate", "Analysis failed", "Analysis failed, retrying", "Analysis pending"}},
		{"Severity", "single_select", []string{"Critical", "High", "Medium", "Low"}},
		{"State", "single_select", []string{"triage", "draft", "published", "closed", "withdrawn"}},
		{"Policy exclusion", "single_select", []string{"Yes", "No"}},
		{"Located", "single_select", []string{"Yes", "No"}},
		{"Component", "text", nil},
		{"Original report", "text", nil},
	} {
		field := github.ProjectField{ID: int64(100 + i), Name: f.name, DataType: f.dataType}
		for _, o := range f.options {
			option := struct {
				ID   string `json:"id"`
				Name struct {
					Raw string `json:"raw"`
				} `json:"name"`
			}{ID: "opt-" + o}
			option.Name.Raw = o
			field.Options = append(field.Options, option)
		}
		p.Fields = append(p.Fields, field)
	}

	return p
}

func (p *Project) field(name string) github.ProjectField {
	return p.Fields[slices.IndexFunc(p.Fields, func(f github.ProjectField) bool { return f.Name == name })]
}

// Value reads a field of an item back as text, the option name for a single select field.
func (p *Project) Value(item int64, field string) string {
	f := p.field(field)
	v, ok := p.Items[item][f.ID]
	if !ok || v == nil {
		return ""
	}
	for _, o := range f.Options {
		if o.ID == v {
			return o.Name.Raw
		}
	}

	return fmt.Sprint(v)
}

// Find returns the item holding ghsa, 0 when none does.
func (p *Project) Find(ghsa string) int64 {
	for id := range p.Items {
		if p.Value(id, "GHSA") == ghsa {
			return id
		}
	}

	return 0
}

// Add creates an item with the given values, by field name and as Value returns them.
func (p *Project) Add(values map[string]any) int64 {
	p.next++
	p.Items[p.next] = map[int64]any{}
	for name, v := range values {
		f := p.field(name)
		for _, o := range f.Options {
			if o.Name.Raw == v {
				v = o.ID
			}
		}
		p.Items[p.next][f.ID] = v
	}

	return p.next
}

func (p *Project) GetProject(context.Context, string, int) (github.Project, error) {
	return github.Project{Public: p.Public}, p.ListErr
}

func (p *Project) ListProjectFields(context.Context, string, int) ([]github.ProjectField, error) {
	return p.Fields, p.ListErr
}

// ListProjectItems encodes the values the way GitHub does.
func (p *Project) ListProjectItems(_ context.Context, _ string, _ int, fields []int64) ([]github.ProjectItem, error) {
	if p.ListErr != nil {
		return nil, p.ListErr
	}
	var items []github.ProjectItem
	for id, values := range p.Items {
		item := github.ProjectItem{ID: id, ContentType: "DraftIssue"}
		item.Content.NodeID = draft(id)
		if n, ok := p.issueOf[id]; ok {
			item.ContentType, item.Content.Number, item.Content.ID = "Issue", n, p.Issues[n].ID
		}
		for _, f := range p.Fields {
			v, ok := values[f.ID]
			if !ok || !slices.Contains(fields, f.ID) {
				continue
			}
			var raw []byte
			switch f.DataType {
			case "text":
				raw, _ = json.Marshal(map[string]any{"raw": v, "html": v})
			case "single_select":
				raw, _ = json.Marshal(map[string]any{"id": v, "name": map[string]any{"raw": p.Value(id, f.Name)}})
			default:
				raw, _ = json.Marshal(v)
			}
			item.Fields = append(item.Fields, struct {
				ID    int64           `json:"id"`
				Value json.RawMessage `json:"value"`
			}{f.ID, raw})
		}
		items = append(items, item)
	}

	return items, nil
}

func (p *Project) CreateDraft(_ context.Context, _ string, _ int, title, body string) (github.ProjectItem, error) {
	if p.Err != nil {
		return github.ProjectItem{}, p.Err
	}
	id := p.Add(nil)
	p.Titles[id], p.Bodies[id] = title, body
	item := github.ProjectItem{ID: id}
	item.Content.NodeID = draft(id)

	return item, nil
}

// IssueOf returns the issue of an item, nil for a draft.
func (p *Project) IssueOf(item int64) *Issue {
	if n, ok := p.issueOf[item]; ok {
		return p.Issues[n]
	}

	return nil
}

func (p *Project) GetRepository(_ context.Context, repo string) (github.Repository, error) {
	private, ok := p.Repos[repo]
	if !ok {
		return github.Repository{}, &github.HTTPError{Status: 404}
	}

	return github.Repository{Private: private}, nil
}

func (p *Project) ListIssues(_ context.Context, repo string) ([]github.Issue, error) {
	if p.ListErr != nil {
		return nil, p.ListErr
	}
	var issues []github.Issue
	for n, i := range p.Issues {
		if i.Repo == repo {
			issues = append(issues, github.Issue{ID: i.ID, Number: n, Title: i.Title, Body: i.Body})
		}
	}

	return issues, nil
}

func (p *Project) CreateIssue(_ context.Context, repo, title, body string) (github.Issue, error) {
	if p.Err != nil || p.IssueErr != nil {
		return github.Issue{}, errors.Join(p.Err, p.IssueErr)
	}
	n := len(p.Issues) + 1
	p.Issues[n] = &Issue{ID: int64(1000 + n), Repo: repo, Title: title, Body: body, State: "open"}

	return github.Issue{ID: int64(1000 + n), Number: n}, nil
}

func (p *Project) UpdateIssue(_ context.Context, repo string, number int, fields map[string]string) error {
	if p.Err != nil || p.IssueErr != nil {
		return errors.Join(p.Err, p.IssueErr)
	}
	i := p.Issues[number]
	if i == nil || i.Repo != repo {
		return &github.HTTPError{Status: 404}
	}
	for k, v := range fields {
		switch k {
		case "body":
			i.Body = v
		case "state":
			i.State = v
		case "state_reason":
			i.StateReason = v
		}
	}

	return nil
}

func (p *Project) AddProjectIssue(_ context.Context, _ string, _ int, issue int64) (github.ProjectItem, error) {
	if p.Err != nil {
		return github.ProjectItem{}, p.Err
	}
	id := p.Add(nil)
	p.issueOf[id] = int(issue - 1000)

	return github.ProjectItem{ID: id, ContentType: "Issue"}, nil
}

func (p *Project) AddSubIssue(_ context.Context, repo string, parent int, child int64) error {
	if p.Err != nil || p.IssueErr != nil {
		return errors.Join(p.Err, p.IssueErr)
	}
	sub := p.Issues[int(child-1000)]
	if p.Issues[parent] == nil || sub == nil || sub.Repo != repo {
		return &github.HTTPError{Status: 422}
	}
	sub.Parent = parent

	return nil
}

func (p *Project) UpdateDraft(_ context.Context, node, body string) error {
	if p.Err != nil {
		return p.Err
	}
	for id := range p.Items {
		if draft(id) == node {
			p.Bodies[id] = body
			return nil
		}
	}

	return fmt.Errorf("no draft %s", node)
}

func draft(id int64) string {
	return fmt.Sprintf("DI_%d", id)
}

func (p *Project) UpdateProjectItem(_ context.Context, _ string, _ int, item int64, fields []github.FieldValue) error {
	if p.Err != nil {
		return p.Err
	}
	if p.UpdateErr != nil {
		return p.UpdateErr
	}
	p.Writes++
	for _, f := range fields {
		p.Items[item][f.ID] = f.Value
	}

	return nil
}
