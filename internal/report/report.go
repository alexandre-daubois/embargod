// Package report holds the triage report, its verification against reality and its rendering.
package report

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/alexandre-daubois/securibot/internal/github"
	"github.com/alexandre-daubois/securibot/internal/repo"
)

// Marker identifies comments posted by securibot.
const Marker = "<!-- securibot -->"

var (
	cweID = regexp.MustCompile(`^CWE-[1-9][0-9]*$`)
	// Base metrics only, in the order mandated by the CVSS 4.0 specification.
	cvss4 = regexp.MustCompile(`^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]$`)

	confidences = []string{"low", "medium", "high"}

	cluePath   = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,200}$`)
	clueSymbol = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,100}$`)
	// A PHP function or method, e.g. http_build_query or SplFixedArray::offsetSet.
	clueEntryPoint = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,100}(::[A-Za-z_][A-Za-z0-9_]{0,100})?$`)
)

const (
	maxClues = 10
	maxLine  = 1_000_000
)

type Report struct {
	Summary          string          `json:"summary"`
	Affected         []Location      `json:"affected"`
	EntryPoints      []string        `json:"entry_points"`
	Related          []Related       `json:"related"`
	CodeReferences   []CodeReference `json:"code_references"`
	PolicyExclusions []PolicyPoint   `json:"policy_exclusions"`
	CWE              []CWE           `json:"cwe"`
	CVSS             CVSS            `json:"cvss"`

	// Duplicates come from the comparator, never from the reader.
	Duplicates []Duplicate `json:"-"`
	// Policy is the path of the repository security policy, empty when there is none.
	Policy string `json:"-"`
	// Removed counts the model claims dropped because they could not be verified.
	Removed int `json:"-"`
}

type Location struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol"`
	Line   int    `json:"line"`
}

// Comparison is everything the comparator learns about the report being triaged: identifiers,
// numbers and CWEs only, the comparator reads the code at these locations to understand the bug.
type Comparison struct {
	Locations   []Location `json:"locations"`
	EntryPoints []string   `json:"entry_points"`
	CWE         []string   `json:"cwe"`
}

type Duplicate struct {
	GHSAID     string `json:"ghsa_id"`
	Confidence string `json:"confidence"`
	Exact      bool   `json:"exact"`
	URL        string `json:"-"`
	Published  bool   `json:"-"`
}

type Related struct {
	Number      int    `json:"number"`
	Confidence  string `json:"confidence"`
	Title       string `json:"-"`
	URL         string `json:"-"`
	PullRequest bool   `json:"-"`
}

type CodeReference struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol"`
	Found  bool   `json:"-"`
}

type PolicyPoint struct {
	Point  string `json:"point"`
	Reason string `json:"reason"`
}

type CWE struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type CVSS struct {
	Vector string `json:"vector"`
	Reason string `json:"reason"`
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var confidence = map[string]any{"type": "string", "enum": confidences, "description": "How sure you are, after comparing the code"}

func list(desc string, props map[string]any) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{
		"type": "object", "properties": props, "required": slices.Sorted(maps.Keys(props)), "additionalProperties": false,
	}}
}

// ReaderProperties is the JSON schema of what the reader, which sees the report, submits.
func ReaderProperties() (map[string]any, []string) {
	return map[string]any{
		"summary": str("One short sentence, 20 words at most: what the report claims and how credible it looks."),
		"affected": list("Where the bug actually lives, after reading the code: at most 10 locations, used to look for duplicates.", map[string]any{
			"path":   str("File path relative to the repository root"),
			"symbol": str("C function, macro or variable name, empty when unknown"),
			"line":   map[string]any{"type": "integer", "description": "Line of the faulty statement in the current code, 0 when unknown"},
		}),
		"entry_points": map[string]any{"type": "array", "description": "PHP functions or methods the report goes through to reach the bug, e.g. http_build_query or SplFixedArray::offsetSet. At most 10.", "items": map[string]any{"type": "string"}},
		"related": list("Public issues or pull requests of this repository already fixing or hardening the same code. Empty when none.", map[string]any{
			"number":     map[string]any{"type": "integer", "description": "Issue or pull request number"},
			"confidence": confidence,
		}),
		"code_references": list("Every file and function or macro the report cites.", map[string]any{
			"path":   str("File path relative to the repository root, as cited"),
			"symbol": str("Function, macro or variable name cited, empty when only a file is cited"),
		}),
		"policy_exclusions": list("Points of the repository security policy that may exclude the report from security handling. Empty when none applies or when there is no policy.", map[string]any{
			"point":  str("The policy point, quoted or closely paraphrased"),
			"reason": str("One sentence on why it may apply to this report"),
		}),
		"cwe": list("Most specific CWE(s) for the weakness, usually one.", map[string]any{
			"id":     str("CWE identifier, e.g. CWE-787"),
			"reason": str("Why this CWE fits"),
		}),
		"cvss": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"vector", "reason"}, "properties": map[string]any{
			"vector": str("CVSS 4.0 base vector, e.g. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			"reason": str("Short justification of the metrics that drive the score"),
		}},
	}, []string{"summary", "affected", "entry_points", "related", "code_references", "policy_exclusions", "cwe", "cvss"}
}

// ComparatorProperties is the JSON schema of what the comparator submits. It holds no free text,
// so the comparator cannot copy anything from the embargoed advisories it reads.
func ComparatorProperties() (map[string]any, []string) {
	return map[string]any{
		"duplicates": list("Other advisories describing the same bug as the given locations. Empty when none.", map[string]any{
			"ghsa_id":    str("GHSA identifier of the other advisory"),
			"confidence": confidence,
			"exact":      map[string]any{"type": "boolean", "description": "True only when the other advisory is the very same bug: same root cause in the same code path, so one fix closes both"},
		}),
	}, []string{"duplicates"}
}

// Clues keeps the affected locations, entry points and CWEs made of plain paths, identifiers and
// numbers, which leaves no room for instructions to travel from the report to the comparator.
func Clues(r Report) Comparison {
	var c Comparison
	for _, l := range r.Affected {
		if len(c.Locations) == maxClues {
			break
		}
		if !cluePath.MatchString(l.Path) || (l.Symbol != "" && !clueSymbol.MatchString(l.Symbol)) || l.Line < 0 || l.Line > maxLine || slices.Contains(c.Locations, l) {
			continue
		}
		c.Locations = append(c.Locations, l)
	}
	for _, e := range r.EntryPoints {
		if len(c.EntryPoints) == maxClues {
			break
		}
		if clueEntryPoint.MatchString(e) && !slices.Contains(c.EntryPoints, e) {
			c.EntryPoints = append(c.EntryPoints, e)
		}
	}
	for _, w := range r.CWE {
		if cweID.MatchString(w.ID) && !slices.Contains(c.CWE, w.ID) {
			c.CWE = append(c.CWE, w.ID)
		}
	}

	return c
}

type IssueGetter interface {
	GetIssue(ctx context.Context, repo string, number int) (github.Issue, error)
}

type Checker struct {
	Repo   string
	Issues IssueGetter
	Code   repo.Repo
	// Advisories indexes the other advisories of the repository by GHSA identifier.
	Advisories map[string]github.Advisory
}

// Verify drops claims pointing at things that do not exist and fills the facts from GitHub.
func (c Checker) Verify(ctx context.Context, r *Report) error {
	// Dropped duplicates are not counted in Removed: the count would tell the reporter that an
	// unpublished advisory came close.
	dups := r.Duplicates[:0]
	for _, d := range r.Duplicates {
		a, ok := c.Advisories[d.GHSAID]
		if !ok || !slices.Contains(confidences, d.Confidence) {
			continue
		}
		d.URL, d.Published = a.HTMLURL, a.State == "published"
		// A reporter learns nothing from an exact duplicate of their own bug, a partial match on an
		// unpublished advisory would reveal another report.
		if !d.Published && !(d.Exact && d.Confidence == "high") {
			continue
		}
		dups = append(dups, d)
	}
	r.Duplicates = dups

	related := r.Related[:0]
	for _, rel := range r.Related {
		if !slices.Contains(confidences, rel.Confidence) {
			r.Removed++
			continue
		}
		issue, err := c.Issues.GetIssue(ctx, c.Repo, rel.Number)
		if errors.Is(err, github.ErrNotFound) {
			r.Removed++
			continue
		}
		if err != nil {
			return err
		}
		rel.Title, rel.URL, rel.PullRequest = issue.Title, issue.HTMLURL, issue.PullRequest != nil
		related = append(related, rel)
	}
	r.Related = related

	for i, ref := range r.CodeReferences {
		found := c.Code.Exists(ref.Path)
		if found && ref.Symbol != "" {
			var err error
			if found, err = c.Code.HasSymbol(ref.Path, ref.Symbol); err != nil {
				return err
			}
		}
		r.CodeReferences[i].Found = found
	}

	cwes := r.CWE[:0]
	for _, w := range r.CWE {
		if !cweID.MatchString(w.ID) {
			r.Removed++
			continue
		}
		cwes = append(cwes, w)
	}
	r.CWE = cwes

	if r.CVSS.Vector != "" && !cvss4.MatchString(r.CVSS.Vector) {
		r.CVSS = CVSS{}
		r.Removed++
	}

	return nil
}

// Render formats the report as the advisory comment.
func Render(r Report) string {
	var b strings.Builder
	b.WriteString(Marker + "\n### Automated triage\n\n")
	b.WriteString("> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.\n\n")
	b.WriteString(text(r.Summary) + "\n")

	b.WriteString("\n#### Possible duplicates\n\n")
	if len(r.Duplicates) == 0 {
		b.WriteString("None found among the repository advisories.\n")
	} else {
		b.WriteString("| Advisory | Status | Confidence |\n|---|---|---|\n")
	}
	for _, d := range r.Duplicates {
		confidence := label(d.Confidence)
		if d.Exact {
			confidence += " • Exact duplicate"
		}
		status := "Unpublished"
		if d.Published {
			status = "Published"
		}
		// No title: the reporter reads this comment, and other advisories may still be under embargo.
		fmt.Fprintf(&b, "| [%s](%s) | %s | %s |\n", d.GHSAID, d.URL, status, confidence)
	}
	b.WriteString("\n_Unpublished advisories are only listed when they are exact duplicates._\n")

	b.WriteString("\n#### Related issues and pull requests\n\n")
	if len(r.Related) == 0 {
		b.WriteString("None found.\n")
	} else {
		b.WriteString("| Issue or PR | Title | Confidence |\n|---|---|---|\n")
	}
	for _, rel := range r.Related {
		kind := "Issue"
		if rel.PullRequest {
			kind = "PR"
		}
		fmt.Fprintf(&b, "| [%s #%d](%s) | %s | %s |\n", kind, rel.Number, rel.URL, text(rel.Title), label(rel.Confidence))
	}

	if len(r.CodeReferences) > 0 {
		b.WriteString("\n#### Code cited by the report\n\n| Reference | Found in the repository |\n|---|---|\n")
		for _, ref := range r.CodeReferences {
			name := code(ref.Path)
			if ref.Symbol != "" {
				name += " " + code(ref.Symbol)
			}
			found := "no"
			if ref.Found {
				found = "yes"
			}
			fmt.Fprintf(&b, "| %s | %s |\n", name, found)
		}
	}

	if r.Policy != "" {
		fmt.Fprintf(&b, "\n#### Security policy\n\nChecked against `%s`.\n\n", r.Policy)
		if len(r.PolicyExclusions) == 0 {
			b.WriteString("Nothing in the policy seems to exclude this report.\n")
		}
		for _, p := range r.PolicyExclusions {
			fmt.Fprintf(&b, "- %s: %s\n", text(p.Point), text(p.Reason))
		}
	}

	b.WriteString("\n#### Weakness and severity\n\n")
	for _, w := range r.CWE {
		fmt.Fprintf(&b, "- %s: %s\n", w.ID, text(w.Reason))
	}
	if r.CVSS.Vector != "" {
		fmt.Fprintf(&b, "- [`%s`](https://www.first.org/cvss/calculator/4.0#%s): %s\n", r.CVSS.Vector, r.CVSS.Vector, text(r.CVSS.Reason))
	}
	if len(r.CWE) == 0 && r.CVSS.Vector == "" {
		b.WriteString("No estimate.\n")
	}

	if r.Removed > 0 {
		fmt.Fprintf(&b, "\n_%d suggestion(s) removed because they could not be verified._\n", r.Removed)
	}

	return b.String()
}

func label(confidence string) string {
	if confidence == "" {
		return ""
	}

	return strings.ToUpper(confidence[:1]) + confidence[1:]
}

// escaper makes model and GitHub text inert: no links, images, HTML, headings or table breaks, so an
// injected report cannot load a remote image carrying data, and a zero-width space after @ breaks mentions.
var escaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`,
	"<", `\<`, ">", `\>`, "!", `\!`, "#", `\#`, "|", `\|`, "~", `\~`, "@", "@\u200b",
)

// text flattens untrusted text on one line and escapes it.
func text(s string) string {
	return escaper.Replace(strings.Join(strings.Fields(s), " "))
}

// code renders untrusted text inside a code span, which cannot hold a backtick.
func code(s string) string {
	return "`" + strings.NewReplacer("`", "'", "|", `\|`).Replace(strings.Join(strings.Fields(s), " ")) + "`"
}
