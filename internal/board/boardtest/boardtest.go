// Package boardtest fakes a GitHub project laid out as docs/setup.md describes.
package boardtest

import (
	"context"
	"encoding/json"
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
}

func New() *Project {
	p := &Project{Items: map[int64]map[int64]any{}, Titles: map[int64]string{}, Bodies: map[int64]string{}}
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
		item := github.ProjectItem{ID: id}
		item.Content.NodeID = draft(id)
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
