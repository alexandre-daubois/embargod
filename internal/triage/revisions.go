package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/php/tamis/internal/engine"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/repo"
	"github.com/php/tamis/internal/report"
	"github.com/php/tamis/internal/sandbox"
)

func advisoryRevision(a github.Advisory, comments []github.Comment, login string, references []string) string {
	input := struct {
		Advisory   github.Advisory
		Comments   []github.Comment
		References []string
	}{Advisory: a, References: references}
	for _, c := range comments {
		if !strings.EqualFold(c.User.Login, login) {
			input.Comments = append(input.Comments, c)
		}
	}
	slices.SortFunc(input.Comments, func(a, b github.Comment) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	data, _ := json.Marshal(input)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func triageRevisions(ctx context.Context, cfg Config, gh GitHub, reader Reader, eng engine.Engine, a github.Advisory, all []github.Advisory, comments []github.Comment, login, revision string, final bool) (bool, error) {
	var visible, private strings.Builder
	var comparisonErr error
	var published, unpublished []github.Advisory
	byID := map[string]github.Advisory{}
	for _, other := range all {
		if other.GHSAID == a.GHSAID {
			continue
		}
		byID[other.GHSAID] = other
		if other.State == "published" {
			published = append(published, other)
		} else {
			unpublished = append(unpublished, other)
		}
	}
	input := a
	for _, c := range comments {
		if !strings.EqualFold(c.User.Login, login) {
			input.Description += "\n\nAdditional report comment:\n" + c.Body
		}
	}
	var r report.Report
	for i, reference := range cfg.References {
		dir, err := os.MkdirTemp("", "tamis-reference-")
		if err != nil {
			return false, err
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "src")
		if err := sandbox.SnapshotSource(ctx, cfg.RepoPath, path, reference); err != nil {
			return false, err
		}
		code := repo.Repo{Dir: path, Context: ctx}
		commit, err := code.Commit()
		if err != nil {
			return false, err
		}
		provenance := fmt.Sprintf("\nRepository: `%s`. Advisory: `%s`.\nSource: `%s` at `%s`. Input revision: `%s`.\n", cfg.Repo, a.GHSAID, reference, commit, revision)
		if i > 0 {
			cited := r
			cited.CodeReferences = slices.Clone(r.CodeReferences)
			if err := (report.Checker{Repo: cfg.Repo, Code: code}).Locate(&cited); err != nil {
				return false, err
			}
			visible.WriteString(provenance + report.RenderCited(cited))
			private.WriteString(provenance + report.RenderCited(cited))
			continue
		}
		local := cfg
		local.RepoPath = path
		if r, err = triage(ctx, local, gh, reader, eng, input, published); err != nil {
			return false, err
		}
		// A failed comparison with unpublished advisories leaves them out of the comment rather than blocking it.
		duplicates, err := findDuplicates(ctx, path, reader, eng, r, unpublished)
		if err != nil {
			comparisonErr = err
			private.WriteString("\nPrivate duplicate search could not complete for this source.\n")
		} else {
			matches := report.Report{Duplicates: duplicates}
			if err := (report.Checker{Advisories: byID}).Verify(ctx, &matches); err != nil {
				return false, err
			}
			r.Duplicates = append(r.Duplicates, matches.Duplicates...)
		}
		visible.WriteString(provenance + report.Render(r))
		private.WriteString(provenance + report.RenderPrivate(r))
	}
	current, err := gh.GetAdvisory(ctx, cfg.Repo, a.GHSAID)
	if err != nil {
		return false, err
	}
	latestComments, err := gh.ListComments(ctx, cfg.Repo, a.GHSAID)
	if err != nil {
		return false, err
	}
	if advisoryRevision(current, latestComments, login, cfg.References) != revision {
		return false, errors.New("the report changed during triage")
	}
	body := visible.String()
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return false, err
	}
	base := reportBase(cfg, a.GHSAID, revision)
	// A posted report closes the advisory, so a partial one is only posted by the last attempt.
	if r.Incomplete && !final {
		if err := os.WriteFile(base+".md", []byte(private.String()), 0o600); err != nil {
			return false, err
		}
		return false, errIncompleteReport
	}
	if err := os.WriteFile(base+".comment.md", []byte(body), 0o600); err != nil {
		return false, err
	}
	if err := gh.PostComment(ctx, cfg.Repo, a.GHSAID, body); err != nil {
		return false, err
	}
	if err := os.WriteFile(base+".md", []byte(private.String()), 0o600); err != nil {
		return true, err
	}
	return true, comparisonErr
}

// reportBase names the private files of one advisory revision, without the GHSA identifier.
func reportBase(cfg Config, ghsa, revision string) string {
	name := sha256.Sum256([]byte(ghsa))

	return filepath.Join(cfg.OutputDir, hex.EncodeToString(name[:])+"-"+revision)
}
