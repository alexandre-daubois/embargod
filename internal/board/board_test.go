package board

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/php/tamis/internal/board/boardtest"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
)

var reported = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func TestOpenRequiresTheDocumentedFields(t *testing.T) {
	for name, tc := range map[string]struct {
		project string
		change  func(*boardtest.Project)
		err     string
	}{
		"complete":       {"php/16", func(*boardtest.Project) {}, ""},
		"no number":      {"php", func(*boardtest.Project) {}, `the project must be given as "org/number"`},
		"no org":         {"/16", func(*boardtest.Project) {}, `the project must be given as "org/number"`},
		"missing field":  {"php/16", func(p *boardtest.Project) { p.Fields[1].Name = "Advisory" }, `the project has no text field "GHSA"`},
		"wrong type":     {"php/16", func(p *boardtest.Project) { p.Fields[3].DataType = "text" }, `the project has no number field "Duplicates"`},
		"missing option": {"php/16", func(p *boardtest.Project) { p.Fields[5].Options = p.Fields[5].Options[1:] }, `the "Priority" field has no "Look first" option`},
		"public":         {"php/16", func(p *boardtest.Project) { p.Public = true }, "the project must be private"},
		"unread GHSA":    {"php/16", func(p *boardtest.Project) { p.Add(map[string]any{"GHSA": 5}) }, "the project item 1 has a value in an unexpected format"},
		"unread count":   {"php/16", func(p *boardtest.Project) { p.Add(map[string]any{"GHSA": "GHSA-old", "Duplicates": "two"}) }, "the project item 1 has a value in an unexpected format"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			tc.change(p)
			_, err := Open(t.Context(), p, tc.project)
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestPrioritize(t *testing.T) {
	older := report.Duplicate{GHSAID: "GHSA-old", Confidence: "high", Exact: true, Confirmed: true, State: "triage", CreatedAt: reported.Add(-time.Hour)}
	for name, tc := range map[string]struct {
		r           report.Report
		priority    string
		duplicateOf string
	}{
		"severe":           {report.Report{Severity: "high", Located: true}, LookFirst, ""},
		"critical":         {report.Report{Severity: "critical", Located: true}, LookFirst, ""},
		"proof of concept": {report.Report{Severity: "high", Located: true, CodeReferences: []report.CodeReference{{Found: true}, {Path: "trigger.py"}}}, LookFirst, ""},
		"medium":           {report.Report{Severity: "medium", Located: true}, Later, ""},
		"no severity":      {report.Report{Located: true}, Later, ""},
		"not located":      {report.Report{Severity: "high", CodeReferences: []report.CodeReference{{Found: true}}}, Later, ""},
		"policy exclusion": {report.Report{Severity: "critical", Located: true, PolicyExclusions: []report.PolicyPoint{{Point: "p"}}}, Later, ""},
		"open duplicate":   {report.Report{Severity: "critical", Duplicates: []report.Duplicate{older}}, Duplicate, "GHSA-old"},
		"settled duplicate": {report.Report{Duplicates: []report.Duplicate{func() report.Duplicate {
			d := older
			d.State, d.Published, d.Confirmed = "published", true, false
			return d
		}()}}, Duplicate, "GHSA-old"},
		"oldest wins": {report.Report{Duplicates: []report.Duplicate{
			func() report.Duplicate {
				d := older
				d.GHSAID = "GHSA-mid"
				d.CreatedAt = reported.Add(-time.Minute)
				return d
			}(),
			older,
		}}, Duplicate, "GHSA-old"},
		"newer duplicate":     {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.CreatedAt = reported.Add(time.Hour); return d }()}}, LookFirst, ""},
		"unconfirmed":         {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Confirmed = false; return d }()}}, LookFirst, ""},
		"not exact":           {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Exact = false; return d }()}}, LookFirst, ""},
		"not high confidence": {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Confidence = "medium"; return d }()}}, LookFirst, ""},
	} {
		t.Run(name, func(t *testing.T) {
			tc.r.CreatedAt = reported
			priority, duplicateOf := Prioritize(tc.r)
			require.Equal(t, tc.priority, priority)
			require.Equal(t, tc.duplicateOf, duplicateOf)
		})
	}
}

func TestPutCreatesOneItemPerAdvisory(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow in foo", HTMLURL: "https://x/GHSA-new", State: "triage", CreatedAt: reported}

	require.NoError(t, b.Put(t.Context(), a, Duplicate, "high", "GHSA-old"))
	require.NoError(t, b.Put(t.Context(), a, LookFirst, "critical", ""))

	require.Len(t, p.Items, 1, "a second put created another item")
	id := p.Find("GHSA-new")
	require.Equal(t, "Overflow in foo", p.Titles[id])
	require.Equal(t, "https://x/GHSA-new", p.Bodies[id])
	require.Equal(t, map[string]string{"GHSA": "GHSA-new", "Reported": "2026-10-20", "State": "triage", "Priority": LookFirst, "Severity": "Critical", "Duplicate of": "", "Duplicates": ""}, values(p, id))
}

func TestPutFindsTheItemOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new", "Priority": Later})
	p.Add(map[string]any{"Priority": Later})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "ghsa-NEW", State: "draft"}, LookFirst, "", ""))

	require.Len(t, p.Items, 2, "the item of a previous run was not reused")
	require.Equal(t, LookFirst, p.Value(id, "Priority"))
	require.Equal(t, "draft", p.Value(id, "State"))
	require.Empty(t, p.Value(id, "Severity"), "an unknown severity was not cleared")
}

func TestPutReportsAFailedWrite(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	p.Err = errors.New("HTTP 403")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, LookFirst, "high", ""))
	require.Empty(t, p.Items)
}

func TestSyncMirrorsStatesAndDuplicates(t *testing.T) {
	p := boardtest.New()
	old := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Priority": LookFirst})
	dup := p.Add(map[string]any{"GHSA": "GHSA-dup", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	other := p.Add(map[string]any{"GHSA": "GHSA-other", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	gone := p.Add(map[string]any{"GHSA": "GHSA-gone", "State": "triage", "Priority": Later})
	manual := p.Add(map[string]any{"Priority": Later})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))

	require.Equal(t, map[string]string{"GHSA": "GHSA-old", "State": "published", "Priority": LookFirst, "Duplicates": "2", "Reported": "", "Severity": "", "Duplicate of": ""}, values(p, old))
	require.Equal(t, Duplicate, p.Value(dup, "Priority"), "the duplicate of a settled report changed priority")
	require.Equal(t, "closed", p.Value(other, "State"))
	require.Equal(t, "triage", p.Value(gone, "State"), "an advisory missing from the list changed state")
	require.Equal(t, Later, p.Value(manual, "Priority"), "an item added by hand was touched")

	writes := p.Writes
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))
	require.Equal(t, writes, p.Writes, "an unchanged board was written again")
}

func TestSyncReportsFailedWrites(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage"})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	p.Err = errors.New("HTTP 403")

	require.Error(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "closed"}}))
}

func values(p *boardtest.Project, id int64) map[string]string {
	v := map[string]string{}
	for _, f := range []string{"GHSA", "Reported", "State", "Priority", "Severity", "Duplicate of", "Duplicates"} {
		v[f] = p.Value(id, f)
	}

	return v
}

func TestHas(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old"})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.True(t, b.Has("ghsa-OLD"))
	require.False(t, b.Has("GHSA-new"))
}

func TestOpenReportsAFailedRead(t *testing.T) {
	p := boardtest.New()
	p.ListErr = errors.New("HTTP 403")

	_, err := Open(t.Context(), p, "php/16")

	require.ErrorIs(t, err, p.ListErr)
}

func TestPutReusesTheDraftWhoseFieldsFailed(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}
	p.UpdateErr = errors.New("HTTP 502")

	require.Error(t, b.Put(t.Context(), a, LookFirst, "high", ""))
	p.UpdateErr = nil
	require.NoError(t, b.Put(t.Context(), a, LookFirst, "high", ""))

	require.Len(t, p.Items, 1, "a failed field update left a second draft")
}

func TestSyncReadsBackTheCountsOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2})
	p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Duplicate of": "GHSA-old"})
	p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Duplicate of": "ghsa-OLD"})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}, {GHSAID: "GHSA-a", State: "triage"}, {GHSAID: "GHSA-b", State: "triage"}}))

	require.Zero(t, p.Writes, "an unchanged count was written again")
}

func TestSyncClearsTheCountOfAReportWithoutDuplicates(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}}))

	require.Equal(t, "0", p.Value(id, "Duplicates"))
}
