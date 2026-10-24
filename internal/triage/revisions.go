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

	"github.com/alexandre-daubois/embargod/internal/engine"
	"github.com/alexandre-daubois/embargod/internal/github"
	"github.com/alexandre-daubois/embargod/internal/repo"
	"github.com/alexandre-daubois/embargod/internal/report"
	"github.com/alexandre-daubois/embargod/internal/sandbox"
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

func triageRevisions(ctx context.Context, cfg Config, gh GitHub, reader Reader, eng engine.Engine, a github.Advisory, all []github.Advisory, comments []github.Comment, login, revision string) (bool, error) {
	var visible strings.Builder
	type branchResult struct {
		report           report.Report
		path, provenance string
	}
	var results []branchResult
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
	for _, reference := range cfg.References {
		path := cfg.RepoPath
		if reference != "HEAD" {
			dir, err := os.MkdirTemp("", "embargod-reference-")
			if err != nil {
				return false, err
			}
			defer os.RemoveAll(dir)
			path = filepath.Join(dir, "src")
			if err := sandbox.SnapshotSource(ctx, cfg.RepoPath, path, reference); err != nil {
				return false, err
			}
		}
		code := repo.Repo{Dir: path, Context: ctx}
		commit, err := code.Commit()
		if err != nil {
			return false, err
		}
		local := cfg
		local.RepoPath = path
		r, err := triage(ctx, local, gh, reader, eng, input, published)
		if err != nil {
			return false, err
		}
		provenance := fmt.Sprintf("\nRepository: `%s`. Advisory: `%s`.\nSource: `%s` at `%s`. Input revision: `%s`.\n", cfg.Repo, a.GHSAID, reference, commit, revision)
		visible.WriteString(provenance + report.Render(r))
		results = append(results, branchResult{r, path, provenance})
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
	name := sha256.Sum256([]byte(a.GHSAID))
	base := filepath.Join(cfg.OutputDir, hex.EncodeToString(name[:])+"-"+revision)
	if err := os.WriteFile(base+".comment.md", []byte(body), 0o600); err != nil {
		return false, err
	}
	if err := gh.PostComment(ctx, cfg.Repo, a.GHSAID, body); err != nil {
		return false, err
	}
	// Publish before examining private candidates: neither their decisions nor failures may affect the comment.
	var private strings.Builder
	var comparisonErr error
	for _, result := range results {
		duplicates, err := findDuplicates(ctx, result.path, reader, eng, result.report, unpublished)
		if err != nil {
			comparisonErr = err
			private.WriteString("\nPrivate duplicate search could not complete for this source.\n")
		} else {
			r := report.Report{Duplicates: duplicates}
			if err := (report.Checker{Advisories: byID}).Verify(ctx, &r); err != nil {
				return true, err
			}
			result.report.Duplicates = append(result.report.Duplicates, r.Duplicates...)
		}
		private.WriteString(result.provenance + report.RenderPrivate(result.report))
	}
	if err := os.WriteFile(base+".md", []byte(private.String()), 0o600); err != nil {
		return true, err
	}
	return true, comparisonErr
}
