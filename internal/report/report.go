// Package report holds the triage report, its verification against reality and its rendering.
package report

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/git-pkgs/cwe"

	"github.com/alexandre-daubois/embargod/internal/github"
	"github.com/alexandre-daubois/embargod/internal/repo"
)

// Marker identifies comments posted by embargod.
const Marker = "<!-- embargod -->"

// FailedMarker identifies the comments of failed attempts, which do not count as a triage.
const FailedMarker = "<!-- embargod failed -->"

var (
	cweID = regexp.MustCompile(`^CWE-[1-9][0-9]*$`)
	// Base metrics only, in the order mandated by the CVSS 4.0 specification.
	cvss4 = regexp.MustCompile(`^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]$`)

	confidences = []string{"low", "medium", "high"}

	cluePath   = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,200}$`)
	clueSymbol = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,100}$`)
	// A public function or method, e.g. http_build_query, SplFixedArray::offsetSet or Request.parse.
	clueEntryPoint = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,100}((::|\.)[A-Za-z_][A-Za-z0-9_]{0,100})?$`)
)

const (
	maxEntryPoints = 10
	maxLine        = 1_000_000
	maxRelated     = 10
	maxCodeRefs    = 30
	maxPolicy      = 10
	maxCWE         = 3
	maxText        = 2_000
	maxTotalText   = 12_000
)

type Report struct {
	Summary          string          `json:"summary"`
	Location         Location        `json:"location"`
	EntryPoints      []string        `json:"entry_points"`
	Related          []Related       `json:"related"`
	CodeReferences   []CodeReference `json:"code_references"`
	PolicyExclusions []PolicyPoint   `json:"policy_exclusions"`
	CWE              []CWE           `json:"cwe"`
	CVSS             CVSS            `json:"cvss"`

	// Duplicates come from the comparator, never from the reader.
	Duplicates []Duplicate `json:"-"`
	// Policies are the files the policy check read, empty when the repository has none.
	Policies []string `json:"-"`
	// Removed counts the model claims dropped because they could not be verified.
	Removed int `json:"-"`
}

type Location struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol"`
	Line   int    `json:"line"`
}

// Comparison is everything the comparator learns about the report being triaged: identifiers,
// numbers and CWEs only, the comparator reads the code at the location to understand the bug.
// It holds a single location, so the same pattern elsewhere cannot pass for the same bug.
type Comparison struct {
	Location    Location `json:"location"`
	EntryPoints []string `json:"entry_points"`
	CWE         []string `json:"cwe"`
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
	properties := map[string]any{
		"summary": str("One short sentence, 20 words at most: what the report claims and how credible it looks. Code identifiers in backticks."),
		"location": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path", "symbol", "line"}, "description": "The faulty statement this report is about, after reading the code, used to look for duplicates. Not the same pattern found elsewhere.", "properties": map[string]any{
			"path":   str("File path relative to the repository root, without backticks, empty when the bug could not be located"),
			"symbol": str("Bare name of the function, method or macro holding the faulty statement, without backticks nor parentheses, empty when unknown"),
			"line":   map[string]any{"type": "integer", "description": "Line of the faulty statement in the current code, 0 when unknown"},
		}},
		"entry_points": map[string]any{"type": "array", "description": "Public functions or methods of the project the report goes through to reach the bug, e.g. http_build_query, SplFixedArray::offsetSet or Request.parse. At most 10.", "items": map[string]any{"type": "string"}},
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
			"reason": str("Why it may apply to this report, 20 words at most, code identifiers in backticks"),
		}),
		"cwe": list("Most specific CWE(s) for the weakness, usually one.", map[string]any{
			"id":     str("CWE identifier, e.g. CWE-787"),
			"reason": str("Why this CWE fits, 15 words at most, code identifiers in backticks"),
		}),
		"cvss": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"vector", "reason"}, "properties": map[string]any{
			"vector": str("CVSS 4.0 base vector, e.g. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			"reason": str("The metrics that drive the score and why, 20 words at most, code identifiers in backticks"),
		}},
	}
	properties["entry_points"].(map[string]any)["maxItems"] = maxEntryPoints
	properties["related"].(map[string]any)["maxItems"] = maxRelated
	properties["code_references"].(map[string]any)["maxItems"] = maxCodeRefs
	properties["policy_exclusions"].(map[string]any)["maxItems"] = maxPolicy
	properties["cwe"].(map[string]any)["maxItems"] = maxCWE

	return properties, []string{"summary", "location", "entry_points", "related", "code_references", "policy_exclusions", "cwe", "cvss"}
}

// ValidateReader bounds every model-controlled collection and string before expensive verification.
func ValidateReader(r Report) error {
	if len(r.Summary) > maxText || len(r.Location.Path) > maxText || len(r.Location.Symbol) > maxText || len(r.EntryPoints) > maxEntryPoints || len(r.Related) > maxRelated || len(r.CodeReferences) > maxCodeRefs || len(r.PolicyExclusions) > maxPolicy || len(r.CWE) > maxCWE || len(r.CVSS.Vector) > maxText || len(r.CVSS.Reason) > maxText {
		return errors.New("the report exceeds its limits")
	}
	for _, text := range r.EntryPoints {
		if len(text) > maxText {
			return errors.New("the report exceeds its limits")
		}
	}
	for _, item := range r.Related {
		if item.Number < 1 || item.Number > maxLine || len(item.Confidence) > maxText {
			return errors.New("the report exceeds its limits")
		}
	}
	for _, item := range r.CodeReferences {
		if len(item.Path) > maxText || len(item.Symbol) > maxText {
			return errors.New("the report exceeds its limits")
		}
	}
	for _, item := range r.PolicyExclusions {
		if len(item.Point) > maxText || len(item.Reason) > maxText {
			return errors.New("the report exceeds its limits")
		}
	}
	for _, item := range r.CWE {
		if len(item.ID) > maxText || len(item.Reason) > maxText {
			return errors.New("the report exceeds its limits")
		}
	}
	total := len(r.Summary) + len(r.Location.Path) + len(r.Location.Symbol) + len(r.CVSS.Vector) + len(r.CVSS.Reason)
	for _, text := range r.EntryPoints {
		total += len(text)
	}
	for _, item := range r.Related {
		total += len(item.Confidence)
	}
	for _, item := range r.CodeReferences {
		total += len(item.Path) + len(item.Symbol)
	}
	for _, item := range r.PolicyExclusions {
		total += len(item.Point) + len(item.Reason)
	}
	for _, item := range r.CWE {
		total += len(item.ID) + len(item.Reason)
	}
	if total > maxTotalText {
		return errors.New("the report exceeds its limits")
	}

	return nil
}

// Clues keeps the location, entry points and CWEs made of plain paths, identifiers and numbers,
// which leaves no room for instructions to travel from the report to the comparator.
func Clues(r Report) Comparison {
	var c Comparison
	if l := r.Location; cluePath.MatchString(l.Path) && (l.Symbol == "" || clueSymbol.MatchString(l.Symbol)) && l.Line >= 0 && l.Line <= maxLine {
		c.Location = l
	}
	for _, e := range r.EntryPoints {
		if len(c.EntryPoints) == maxEntryPoints {
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

// KeepCited drops the code references the report text does not name, which the reader tends to add
// from its own investigation: the section lists what the report cites, found or not.
func (r *Report) KeepCited(reportText string) {
	cited := r.CodeReferences[:0]
	for _, ref := range r.CodeReferences {
		name := ref.Symbol
		if name == "" && ref.Path != "" {
			name = path.Base(ref.Path)
		}
		if name != "" && strings.Contains(reportText, name) {
			cited = append(cited, ref)
		}
	}
	r.CodeReferences = cited
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
	seen := map[string]bool{}
	for _, d := range r.Duplicates {
		a, ok := c.Advisories[d.GHSAID]
		key := strings.ToLower(d.GHSAID)
		if !ok || seen[key] || !slices.Contains(confidences, d.Confidence) {
			continue
		}
		seen[key] = true
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
		// A symbol cited without a file is looked up in the whole repository.
		found := ref.Path == "" || c.Code.Exists(ref.Path)
		if found && ref.Symbol != "" {
			var err error
			if found, err = c.Code.HasSymbol(ref.Path, ref.Symbol); err != nil {
				return err
			}
		}
		r.CodeReferences[i].Found = found && (ref.Path != "" || ref.Symbol != "")
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
		fmt.Fprintf(&b, "| [%s #%d](%s) | %s | %s |\n", kind, rel.Number, rel.URL, cell(rel.Title), label(rel.Confidence))
	}

	if len(r.CodeReferences) > 0 {
		b.WriteString("\n#### Code cited by the report\n\n| Reference | Found in the repository |\n|---|---|\n")
		for _, ref := range r.CodeReferences {
			var parts []string
			for _, p := range []string{ref.Path, ref.Symbol} {
				if strings.TrimSpace(p) != "" {
					parts = append(parts, code(p))
				}
			}
			name := strings.Join(parts, " ")
			found := "no"
			if ref.Found {
				found = "yes"
			}
			fmt.Fprintf(&b, "| %s | %s |\n", name, found)
		}
	}

	if len(r.Policies) > 0 {
		files := make([]string, 0, len(r.Policies))
		for _, p := range r.Policies {
			files = append(files, code(p))
		}
		fmt.Fprintf(&b, "\n#### Security policy\n\nChecked against %s.\n\n", strings.Join(files, ", "))
		if len(r.PolicyExclusions) == 0 {
			b.WriteString("Nothing in the policy seems to exclude this report.\n")
		}
		for _, p := range r.PolicyExclusions {
			fmt.Fprintf(&b, "- %s: %s\n", text(p.Point), text(p.Reason))
		}
	}

	b.WriteString("\n#### Weakness and severity\n\n")
	if len(r.CWE) == 0 && r.CVSS.Vector == "" {
		b.WriteString("No estimate.\n")
	} else {
		b.WriteString("| | Estimate | Why |\n|---|---|---|\n")
	}
	for _, w := range r.CWE {
		estimate := fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", w.ID, strings.TrimPrefix(w.ID, "CWE-"))
		// Deprecated weaknesses and ones newer than the catalogue keep their number only.
		if _, entry, ok := cwe.Lookup(w.ID); ok {
			estimate += " " + cell(entry.Name)
		}
		fmt.Fprintf(&b, "| CWE | %s | %s |\n", estimate, cell(w.Reason))
	}
	if r.CVSS.Vector != "" {
		fmt.Fprintf(&b, "| CVSS 4.0 | [`%s`](https://www.first.org/cvss/calculator/4.0#%s) | %s |\n", strings.TrimPrefix(r.CVSS.Vector, "CVSS:4.0/"), r.CVSS.Vector, cell(r.CVSS.Reason))
	}

	if r.Removed > 0 {
		fmt.Fprintf(&b, "\n_%d suggestion(s) removed because they could not be verified._\n", r.Removed)
	}

	return b.String()
}

// Failed records a failed attempt, so a hostile report that never completes is not retried indefinitely.
func Failed(retry bool) string {
	if retry {
		return FailedMarker + "\n### Automated triage\n\nThe automated triage could not complete. It will be retried.\n"
	}

	return FailedMarker + "\n### Automated triage\n\nThe automated triage could not complete. A maintainer must review this report manually.\n"
}

func label(confidence string) string {
	if confidence == "" {
		return ""
	}

	return strings.ToUpper(confidence[:1]) + confidence[1:]
}

// escaper makes model and GitHub text inert: no links, images, HTML, entities, headings or table breaks, so an
// injected report cannot load a remote image carrying data, and a zero-width space after @ breaks mentions.
var escaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`,
	"<", `\<`, ">", `\>`, "!", `\!`, "#", `\#`, "|", `\|`, "~", `\~`, "&", `\&`, "@", "@\u200b",
)

// text flattens untrusted text on one line and escapes it, except inside its code spans, which
// GitHub renders verbatim: no link, image, HTML nor mention can live there.
func text(s string) string {
	return inline(s, false)
}

// cell is text for a table cell, where a pipe ends the cell even inside a code span.
func cell(s string) string {
	return inline(s, true)
}

func inline(s string, table bool) string {
	parts := strings.Split(strings.Join(strings.Fields(s), " "), "`")
	var b strings.Builder
	for i, p := range parts {
		switch {
		case i%2 == 0:
			b.WriteString(escaper.Replace(p))
		case i == len(parts)-1:
			// An unmatched backtick opens no code span.
			b.WriteString("\\`" + escaper.Replace(p))
		case p != "":
			if table {
				p = strings.ReplaceAll(p, "|", `\|`)
			}
			b.WriteString("`" + p + "`")
		}
	}

	return b.String()
}

// code renders untrusted text inside a code span, which cannot hold a backtick.
func code(s string) string {
	return "`" + strings.NewReplacer("`", "'", "|", `\|`).Replace(strings.Join(strings.Fields(s), " ")) + "`"
}
