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
)

type Report struct {
	Summary          string          `json:"summary"`
	Duplicates       []Duplicate     `json:"duplicates"`
	Related          []Related       `json:"related"`
	CodeReferences   []CodeReference `json:"code_references"`
	PolicyExclusions []PolicyPoint   `json:"policy_exclusions"`
	CWE              []CWE           `json:"cwe"`
	CVSS             CVSS            `json:"cvss"`

	// Policy is the path of the repository security policy, empty when there is none.
	Policy string `json:"-"`
	// Removed counts the model claims dropped because they could not be verified.
	Removed int `json:"-"`
}

type Duplicate struct {
	GHSAID     string `json:"ghsa_id"`
	Confidence string `json:"confidence"`
	Exact      bool   `json:"exact"`
	Title      string `json:"-"`
	URL        string `json:"-"`
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

// Properties is the JSON schema of the report, used as the submit tool input.
func Properties() (map[string]any, []string) {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	confidence := map[string]any{"type": "string", "enum": confidences, "description": "How sure you are, after comparing the code"}
	list := func(desc string, props map[string]any) map[string]any {
		return map[string]any{"type": "array", "description": desc, "items": map[string]any{
			"type": "object", "properties": props, "required": slices.Sorted(maps.Keys(props)), "additionalProperties": false,
		}}
	}

	return map[string]any{
		"summary": str("One short sentence, 20 words at most: what the report claims and how credible it looks."),
		"duplicates": list("Other advisories of this repository describing the same bug. Empty when none.", map[string]any{
			"ghsa_id":    str("GHSA identifier of the other advisory"),
			"confidence": confidence,
			"exact":      map[string]any{"type": "boolean", "description": "True only when both reports describe the very same bug: same root cause in the same code path, so one fix closes both"},
		}),
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
	}, []string{"summary", "duplicates", "related", "code_references", "policy_exclusions", "cwe", "cvss"}
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
	dups := r.Duplicates[:0]
	for _, d := range r.Duplicates {
		a, ok := c.Advisories[d.GHSAID]
		if !ok || !slices.Contains(confidences, d.Confidence) {
			r.Removed++
			continue
		}
		d.Title, d.URL = a.Summary, a.HTMLURL
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
	b.WriteString(inline(r.Summary) + "\n")

	b.WriteString("\n#### Possible duplicates\n\n")
	if len(r.Duplicates) == 0 {
		b.WriteString("None found among the repository advisories.\n")
	} else {
		b.WriteString("| Advisory | Title | Confidence |\n|---|---|---|\n")
	}
	for _, d := range r.Duplicates {
		confidence := label(d.Confidence)
		if d.Exact {
			confidence += " • Exact duplicate"
		}
		fmt.Fprintf(&b, "| [%s](%s) | %s | %s |\n", d.GHSAID, d.URL, cell(d.Title), confidence)
	}

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
		fmt.Fprintf(&b, "| [%s #%d](%s) | %s | %s |\n", kind, rel.Number, rel.URL, cell(rel.Title), label(rel.Confidence))
	}

	if len(r.CodeReferences) > 0 {
		b.WriteString("\n#### Code cited by the report\n\n| Reference | Found in the repository |\n|---|---|\n")
		for _, ref := range r.CodeReferences {
			name := "`" + inline(ref.Path) + "`"
			if ref.Symbol != "" {
				name += " `" + inline(ref.Symbol) + "`"
			}
			found := "no"
			if ref.Found {
				found = "yes"
			}
			fmt.Fprintf(&b, "| %s | %s |\n", strings.ReplaceAll(name, "|", `\|`), found)
		}
	}

	if r.Policy != "" {
		fmt.Fprintf(&b, "\n#### Security policy\n\nChecked against `%s`.\n\n", r.Policy)
		if len(r.PolicyExclusions) == 0 {
			b.WriteString("Nothing in the policy seems to exclude this report.\n")
		}
		for _, p := range r.PolicyExclusions {
			fmt.Fprintf(&b, "- %s: %s\n", inline(p.Point), inline(p.Reason))
		}
	}

	b.WriteString("\n#### Weakness and severity\n\n")
	for _, w := range r.CWE {
		fmt.Fprintf(&b, "- %s: %s\n", w.ID, inline(w.Reason))
	}
	if r.CVSS.Vector != "" {
		fmt.Fprintf(&b, "- [`%s`](https://www.first.org/cvss/calculator/4.0#%s): %s\n", r.CVSS.Vector, r.CVSS.Vector, inline(r.CVSS.Reason))
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

// inline flattens model output on one line and stops it from pinging people: a zero-width space after @ breaks GitHub mentions.
func inline(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "@", "@​")), " ")
}

func cell(s string) string {
	return strings.ReplaceAll(inline(s), "|", `\|`)
}
