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

func TestTriageOf(t *testing.T) {
	older := report.Duplicate{GHSAID: "GHSA-old", Confidence: "high", Exact: true, Confirmed: true, State: "triage", CreatedAt: reported.Add(-time.Hour)}
	for name, tc := range map[string]struct {
		r           report.Report
		priority    string
		duplicateOf string
	}{
		"severe":           {report.Report{Severity: "high", Located: true}, LookFirst, ""},
		"critical":         {report.Report{Severity: "critical", Located: true}, LookFirst, ""},
		"proof of concept": {report.Report{Severity: "high", Located: true, CodeReferences: []report.CodeReference{{Found: true}, {Path: "trigger.py"}}}, LookFirst, ""},
		"medium":           {report.Report{Severity: "medium", Located: true}, WhenPossible, ""},
		"no severity":      {report.Report{Located: true}, WhenPossible, ""},
		"not located":      {report.Report{Severity: "high", CodeReferences: []report.CodeReference{{Found: true}}}, WhenPossible, ""},
		"policy exclusion": {report.Report{Severity: "critical", Located: true, PolicyExclusions: []report.PolicyPoint{{Point: "p"}}}, WhenPossible, ""},
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
			triage := TriageOf(tc.r)
			require.Equal(t, tc.priority, triage.Priority())
			require.Equal(t, tc.duplicateOf, triage.DuplicateOf)
		})
	}
}

func TestPutCreatesOneItemPerAdvisory(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow in foo", HTMLURL: "https://x/GHSA-new", State: "triage", CreatedAt: reported}

	require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Excluded: true}, "first comment"))
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "critical", Located: true}, "second comment"))

	require.Len(t, p.Items, 1, "a second put created another item")
	id := p.Find("GHSA-new")
	require.Equal(t, "Overflow in foo", p.Titles[id])
	require.Equal(t, "https://x/GHSA-new\n\nsecond comment", p.Bodies[id], "the draft body misses the latest comment")
	require.Equal(t, map[string]string{"GHSA": "GHSA-new", "Reported": "2026-10-20", "State": "triage", "Priority": LookFirst, "Severity": "Critical", "Duplicate of": "", "Duplicates": "", "Policy exclusion": "No", "Located": "Yes"}, values(p, id))
}

func TestPutFindsTheItemOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new", "Priority": WhenPossible})
	p.Add(map[string]any{"Priority": WhenPossible})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "ghsa-NEW", State: "draft"}, LookFirst, &Triage{}, ""))

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

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, LookFirst, &Triage{Severity: "high"}, ""))
	require.Empty(t, p.Items)
}

func TestSyncMirrorsStatesAndDuplicates(t *testing.T) {
	p := boardtest.New()
	old := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Priority": LookFirst})
	dup := p.Add(map[string]any{"GHSA": "GHSA-dup", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	other := p.Add(map[string]any{"GHSA": "GHSA-other", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	gone := p.Add(map[string]any{"GHSA": "GHSA-gone", "State": "triage", "Priority": WhenPossible})
	manual := p.Add(map[string]any{"Priority": WhenPossible})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))

	require.Equal(t, map[string]string{"GHSA": "GHSA-old", "State": "published", "Priority": LookFirst, "Duplicates": "2", "Reported": "", "Severity": "", "Duplicate of": "", "Policy exclusion": "", "Located": ""}, values(p, old))
	require.Equal(t, Duplicate, p.Value(dup, "Priority"), "the duplicate of a settled report changed priority")
	require.Equal(t, "closed", p.Value(other, "State"))
	require.Equal(t, "triage", p.Value(gone, "State"), "an advisory missing from the list changed state")
	require.Equal(t, WhenPossible, p.Value(manual, "Priority"), "an item added by hand was touched")

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
	for _, f := range []string{"GHSA", "Reported", "State", "Priority", "Severity", "Duplicate of", "Duplicates", "Policy exclusion", "Located"} {
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

	require.Error(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high"}, ""))
	p.UpdateErr = nil
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high"}, ""))

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

func TestPutKeepsTheDraftBodyWithoutAComment(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", HTMLURL: "https://x/GHSA-new"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, ""))
	id := p.Find("GHSA-new")
	require.Equal(t, "https://x/GHSA-new", p.Bodies[id])
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high"}, "the comment"))
	require.NoError(t, b.Put(t.Context(), a, AnalysisFailed, nil, ""))

	require.Equal(t, "https://x/GHSA-new\n\nthe comment", p.Bodies[id], "a put without comment erased the body")
}

func TestPutUpdatesTheDraftOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new"})
	p.Bodies[id] = "https://x/GHSA-new"
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", HTMLURL: "https://x/GHSA-new"}, LookFirst, &Triage{Severity: "high"}, "the comment"))

	require.Equal(t, "https://x/GHSA-new\n\nthe comment", p.Bodies[id])
}

func TestPutReportsAFailedDraftUpdate(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-new"})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	p.Err = errors.New("github: GraphQL request failed")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, LookFirst, &Triage{Severity: "high"}, "the comment"))
}

func TestPutClearsTheTriageOfAStatus(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Located: true}, ""))
	require.NoError(t, b.Put(t.Context(), a, AnalysisFailed, nil, "note"))

	id := p.Find("GHSA-new")
	for _, f := range []string{"Severity", "Duplicate of", "Policy exclusion", "Located"} {
		require.Empty(t, p.Value(id, f), "%s outlived the triage", f)
	}
}

func TestSyncRanksEveryTriageAgain(t *testing.T) {
	p := boardtest.New()
	stale := p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Priority": WhenPossible, "Severity": "Critical", "Policy exclusion": "No", "Located": "Yes"})
	dup := p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Priority": LookFirst, "Severity": "High", "Policy exclusion": "No", "Located": "Yes", "Duplicate of": "GHSA-a"})
	excluded := p.Add(map[string]any{"GHSA": "GHSA-c", "State": "triage", "Priority": LookFirst, "Severity": "High", "Policy exclusion": "Yes", "Located": "Yes"})
	status := p.Add(map[string]any{"GHSA": "GHSA-d", "State": "triage", "Priority": AnalysisFailed})
	older := p.Add(map[string]any{"GHSA": "GHSA-e", "State": "triage", "Priority": LookFirst, "Severity": "Low"})
	b, err := Open(t.Context(), p, "php/16")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), nil))

	require.Equal(t, LookFirst, p.Value(stale, "Priority"), "a triage ranked by an older rule kept its priority")
	require.Equal(t, Duplicate, p.Value(dup, "Priority"))
	require.Equal(t, WhenPossible, p.Value(excluded, "Priority"))
	require.Equal(t, AnalysisFailed, p.Value(status, "Priority"), "a status was ranked as a triage")
	require.Equal(t, LookFirst, p.Value(older, "Priority"), "an item without the ranking inputs was ranked")

	writes := p.Writes
	require.NoError(t, b.Sync(t.Context(), nil))
	require.Equal(t, writes, p.Writes, "a ranked board was written again")
}
