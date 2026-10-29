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
			_, err := Open(t.Context(), p, tc.project, "", "php/php-src")
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
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow in foo", HTMLURL: "https://x/GHSA-new", State: "triage", CreatedAt: reported}

	require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Excluded: true}, "first comment"))
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "critical", Located: true, Component: "ext/foo"}, "second comment"))

	require.Len(t, p.Items, 1, "a second put created another item")
	id := p.Find("GHSA-new")
	require.Equal(t, "Overflow in foo", p.Titles[id])
	require.Equal(t, "https://x/GHSA-new\n\nsecond comment", p.Bodies[id], "the draft body misses the latest comment")
	require.Equal(t, map[string]string{"GHSA": "GHSA-new", "Reported": "2026-10-20", "State": "triage", "Priority": LookFirst, "Severity": "Critical", "Duplicate of": "", "Duplicates": "", "Policy exclusion": "No", "Located": "Yes", "Component": "ext/foo", "Original report": ""}, values(p, id))
}

func TestPutFindsTheItemOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new", "Priority": WhenPossible})
	p.Add(map[string]any{"Priority": WhenPossible})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "ghsa-NEW", State: "draft"}, LookFirst, &Triage{}, ""))

	require.Len(t, p.Items, 2, "the item of a previous run was not reused")
	require.Equal(t, LookFirst, p.Value(id, "Priority"))
	require.Equal(t, "draft", p.Value(id, "State"))
	require.Empty(t, p.Value(id, "Severity"), "an unknown severity was not cleared")
}

func TestPutReportsAFailedWrite(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
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
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))

	require.Equal(t, map[string]string{"GHSA": "GHSA-old", "State": "published", "Priority": LookFirst, "Duplicates": "2", "Reported": "", "Severity": "", "Duplicate of": "", "Policy exclusion": "", "Located": "", "Component": "", "Original report": "GHSA-old"}, values(p, old))
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
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	p.Err = errors.New("HTTP 403")

	require.Error(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "closed"}}))
}

func values(p *boardtest.Project, id int64) map[string]string {
	v := map[string]string{}
	for _, f := range []string{"GHSA", "Reported", "State", "Priority", "Severity", "Duplicate of", "Duplicates", "Policy exclusion", "Located", "Component", "Original report"} {
		v[f] = p.Value(id, f)
	}

	return v
}

func TestHas(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old"})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.True(t, b.Has("ghsa-OLD"))
	require.False(t, b.Has("GHSA-new"))
}

func TestOpenReportsAFailedRead(t *testing.T) {
	p := boardtest.New()
	p.ListErr = errors.New("HTTP 403")

	_, err := Open(t.Context(), p, "php/16", "", "php/php-src")

	require.ErrorIs(t, err, p.ListErr)
}

func TestPutReusesTheDraftWhoseFieldsFailed(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
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
	p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2, "Original report": "GHSA-old"})
	p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Duplicate of": "GHSA-old", "Original report": "GHSA-old"})
	p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Duplicate of": "ghsa-OLD", "Original report": "ghsa-OLD"})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}, {GHSAID: "GHSA-a", State: "triage"}, {GHSAID: "GHSA-b", State: "triage"}}))

	require.Zero(t, p.Writes, "an unchanged count was written again")
}

func TestSyncClearsTheCountOfAReportWithoutDuplicates(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}}))

	require.Equal(t, "0", p.Value(id, "Duplicates"))
}

func TestPutKeepsTheDraftBodyWithoutAComment(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
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
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", HTMLURL: "https://x/GHSA-new"}, LookFirst, &Triage{Severity: "high"}, "the comment"))

	require.Equal(t, "https://x/GHSA-new\n\nthe comment", p.Bodies[id])
}

func TestPutReportsAFailedDraftUpdate(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-new"})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	p.Err = errors.New("github: GraphQL request failed")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, LookFirst, &Triage{Severity: "high"}, "the comment"))
}

func TestPutClearsTheTriageOfAStatus(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Located: true, Component: "ext/foo"}, ""))
	require.NoError(t, b.Put(t.Context(), a, AnalysisFailed, nil, "note"))

	id := p.Find("GHSA-new")
	for _, f := range []string{"Severity", "Duplicate of", "Policy exclusion", "Located", "Component"} {
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
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
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

func TestTriageOfNamesTheComponentOfTheFaultyStatement(t *testing.T) {
	for file, want := range map[string]string{
		"ext/pgsql/pgsql.c":       "ext/pgsql",
		"sapi/fpm/fpm/fpm_main.c": "sapi/fpm",
		"Zend/zend_execute.c":     "Zend",
		"main/streams/streams.c":  "main/streams",
		"main.c":                  "",
	} {
		require.Equal(t, want, TriageOf(report.Report{Location: report.Location{Path: file}, Located: true}).Component, file)
	}
	require.Empty(t, TriageOf(report.Report{Location: report.Location{Path: "ext/pgsql/pgsql.c"}}).Component, "an unlocated statement got a component")
	require.Equal(t, "sapi/fpm", TriageOf(report.Report{Component: "sapi/fpm", Location: report.Location{Path: "main/fastcgi.c"}, Located: true}).Component, "the component the model named lost to the path")
}

func TestSyncGroupsEveryReportUnderItsOldest(t *testing.T) {
	p := boardtest.New()
	root := p.Add(map[string]any{"GHSA": "GHSA-root", "State": "triage"})
	mid := p.Add(map[string]any{"GHSA": "GHSA-mid", "State": "triage", "Duplicate of": "GHSA-root"})
	leaf := p.Add(map[string]any{"GHSA": "GHSA-leaf", "State": "triage", "Duplicate of": "GHSA-mid"})
	orphan := p.Add(map[string]any{"GHSA": "GHSA-orphan", "State": "triage", "Duplicate of": "GHSA-gone"})
	alone := p.Add(map[string]any{"GHSA": "GHSA-alone", "State": "triage", "Original report": "GHSA-stale"})
	loopA := p.Add(map[string]any{"GHSA": "GHSA-loop-a", "State": "triage", "Duplicate of": "GHSA-loop-b"})
	p.Add(map[string]any{"GHSA": "GHSA-loop-b", "State": "triage", "Duplicate of": "GHSA-loop-a"})
	b, err := Open(t.Context(), p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), nil))

	require.Equal(t, "GHSA-root", p.Value(root, "Original report"), "the oldest report is missing from its group")
	require.Equal(t, "GHSA-root", p.Value(mid, "Original report"))
	require.Equal(t, "GHSA-root", p.Value(leaf, "Original report"), "a chain of duplicates was split")
	require.Equal(t, "GHSA-gone", p.Value(orphan, "Original report"), "a report whose oldest has no item lost its group")
	require.Empty(t, p.Value(alone, "Original report"), "a report without duplicates kept a stale group")
	require.NotEmpty(t, p.Value(loopA, "Original report"), "a loop of duplicates did not end")
}

func TestOpenRefusesAnIssuesRepositoryThatCouldPublishReports(t *testing.T) {
	for name, tc := range map[string]struct {
		issues, err string
	}{
		"private":             {"php/php-src-security", ""},
		"public":              {"php/php-src", "the issues repository must not be the repository of the advisories"},
		"public elsewhere":    {"php/web-php", "the issues repository must be private"},
		"advisory repository": {"PHP/PHP-SRC", "the issues repository must not be the repository of the advisories"},
		"unknown":             {"php/missing", "github: HTTP 404"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			p.Repos["php/web-php"] = false

			_, err := Open(t.Context(), p, "php/16", tc.issues, "php/php-src")

			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
			require.Empty(t, p.Issues)
		})
	}
}

func TestPutCreatesAPrivateIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow found by @someone", HTMLURL: "https://x/GHSA-new", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, "pending"))
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{Severity: "high", Located: true}, "the comment"))

	id := p.Find("GHSA-new")
	issue := p.IssueOf(id)
	require.NotNil(t, issue, "the item is a draft")
	require.Len(t, p.Issues, 1, "a second put created another issue")
	require.Equal(t, "php/php-src-security", issue.Repo)
	require.Equal(t, "Overflow found by @​someone", issue.Title, "a mention in the title would notify")
	require.Equal(t, "https://x/GHSA-new\n\nthe comment\n\n<!-- tamis-issue GHSA-new -->", issue.Body)
	require.Equal(t, "open", issue.State)
	require.Empty(t, p.Titles, "a draft was created next to the issue")
	require.Equal(t, LookFirst, p.Value(id, "Priority"))
}

func TestPutClosesTheIssueOfASettledAdvisory(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "published"}, LookFirst, &Triage{}, ""))

	issue := p.IssueOf(p.Find("GHSA-new"))
	require.Equal(t, "closed", issue.State)
	require.Equal(t, "completed", issue.StateReason)
}

func TestPutReportsAFailedIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	p.IssueErr = errors.New("HTTP 403")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}, LookFirst, &Triage{}, ""))
	require.Empty(t, p.Items, "an item was added without its issue")
}

func TestPutKeepsTheDraftsOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-old"})
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-old", HTMLURL: "https://x/GHSA-old", State: "triage"}, LookFirst, &Triage{}, "the comment"))

	require.Nil(t, p.IssueOf(id))
	require.Empty(t, p.Issues, "a draft was turned into a second item")
	require.Equal(t, "https://x/GHSA-old\n\nthe comment", p.Bodies[id])
}

func TestSyncMirrorsTheAdvisoryStateOnItsIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	for _, g := range []string{"GHSA-a", "GHSA-b", "GHSA-c"} {
		require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: g, Summary: g, State: "triage"}, LookFirst, &Triage{}, ""))
	}

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-a", State: "published"}, {GHSAID: "GHSA-b", State: "closed"}, {GHSAID: "GHSA-c", State: "draft"}}))

	require.Equal(t, "completed", p.IssueOf(p.Find("GHSA-a")).StateReason)
	require.Equal(t, "closed", p.IssueOf(p.Find("GHSA-b")).State)
	require.Equal(t, "not_planned", p.IssueOf(p.Find("GHSA-b")).StateReason)
	require.Equal(t, "open", p.IssueOf(p.Find("GHSA-c")).State, "an accepted advisory closed its issue")

	p.IssueErr = errors.New("HTTP 403")
	require.Error(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-c", State: "closed"}}))
	require.Equal(t, "draft", p.Value(p.Find("GHSA-c"), "State"), "the field moved while its issue stayed open")
}

func TestSyncNestsEveryDuplicateUnderItsOriginal(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	put := func(g, dup string) {
		require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: g, Summary: g, State: "triage"}, Duplicate, &Triage{DuplicateOf: dup}, ""))
	}
	put("GHSA-root", "")
	put("GHSA-mid", "GHSA-root")
	put("GHSA-leaf", "GHSA-mid")
	put("GHSA-orphan", "GHSA-gone")
	p.IssueErr = errors.New("HTTP 502")

	require.Error(t, b.Sync(t.Context(), nil))
	require.Empty(t, p.Value(p.Find("GHSA-leaf"), "Original report"), "the group was written before its sub-issue")

	p.IssueErr = nil
	require.NoError(t, b.Sync(t.Context(), nil))

	root := p.IssueOf(p.Find("GHSA-root"))
	require.Zero(t, root.Parent, "the original became a sub-issue of itself")
	for _, g := range []string{"GHSA-mid", "GHSA-leaf"} {
		require.Equal(t, 1, p.IssueOf(p.Find(g)).Parent, "%s is not under its original", g)
	}
	require.Zero(t, p.IssueOf(p.Find("GHSA-orphan")).Parent, "a report whose original has no issue got a parent")
	require.Equal(t, "GHSA-gone", p.Value(p.Find("GHSA-orphan"), "Original report"))
}

func TestPutAttachesTheIssueOfARunThatFailedToAddIt(t *testing.T) {
	p := boardtest.New()
	const ghsa = "GHSA-aaaa-bbbb-cccc"
	a := github.Advisory{GHSAID: ghsa, Summary: "s", HTMLURL: "https://x/" + ghsa, State: "triage"}
	p.Issues[1] = &boardtest.Issue{ID: 1001, Repo: "php/php-src-security", Title: "s", Body: "https://x/" + ghsa + "\n\n<!-- tamis-issue " + ghsa + " -->", State: "open"}
	p.Issues[2] = &boardtest.Issue{ID: 1002, Repo: "php/php-src-security", Title: "by hand", Body: "no marker", State: "open"}

	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{}, "the comment"))

	require.Len(t, p.Issues, 2, "a second issue was created for the same advisory")
	issue := p.IssueOf(p.Find(ghsa))
	require.Equal(t, int64(1001), issue.ID, "the issue of the previous run was not reused")
	require.Contains(t, issue.Body, "the comment")
	require.Contains(t, issue.Body, "<!-- tamis-issue "+ghsa+" -->", "the update dropped the marker")
}

func TestPutMarksEveryIssueWithItsAdvisory(t *testing.T) {
	p := boardtest.New()
	const ghsa = "GHSA-dddd-eeee-ffff"
	b, err := Open(t.Context(), p, "php/16", "php/php-src-security", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: ghsa, Summary: "s", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, "pending"))
	require.Contains(t, p.IssueOf(p.Find(ghsa)).Body, "<!-- tamis-issue "+ghsa+" -->")
	require.NoError(t, b.Put(t.Context(), a, LookFirst, &Triage{}, "the comment"))
	require.Contains(t, p.IssueOf(p.Find(ghsa)).Body, "<!-- tamis-issue "+ghsa+" -->", "the update dropped the marker")
}
