package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/php/tamis/internal/board"
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

func triageRevisions(ctx context.Context, cfg Config, gh GitHub, reader Reader, eng engine.Engine, b *board.Board, a github.Advisory, all []github.Advisory, comments []github.Comment, backfill bool, login, revision string, final bool, sourceDir string, log *slog.Logger) (bool, error) {
	var comparisonErr error
	var others []github.Advisory
	byID := map[string]github.Advisory{}
	for _, other := range all {
		if other.GHSAID == a.GHSAID {
			continue
		}
		byID[other.GHSAID] = other
		others = append(others, other)
	}
	input := a
	for _, c := range comments {
		if !strings.EqualFold(c.User.Login, login) {
			input.Description += "\n\nAdditional report comment:\n" + c.Body
		}
	}
	var r report.Report
	var sources, privateNote string
	for i, reference := range cfg.References {
		log.Info("preparing the source", "source", reference)
		start := time.Now()
		path := filepath.Join(sourceDir, strconv.Itoa(i))
		if _, err := os.Stat(path); err != nil {
			prepare := worktree
			if i == 0 {
				log.Info("copying the analysed source", "source", reference)
				prepare = sandbox.SnapshotSource
			}
			if err := prepare(ctx, cfg.RepoPath, path, reference); err != nil {
				_ = os.RemoveAll(path)
				return false, err
			}
		}
		log.Info("source ready", "source", reference, "duration", time.Since(start).Round(time.Second))
		code := repo.Repo{Dir: path, Context: ctx}
		commit, err := code.Commit()
		if err != nil {
			return false, err
		}
		sources += fmt.Sprintf("Source: `%s` at `%s`.\n", reference, commit)
		if i > 0 {
			cited := report.Report{CodeReferences: slices.Clone(r.CodeReferences)}
			if err := (report.Checker{Repo: cfg.Repo, Code: code}).Locate(&cited); err != nil {
				return false, err
			}
			cited.Branch = reference
			r.Elsewhere = append(r.Elsewhere, cited)
			continue
		}
		local := cfg
		local.RepoPath = path
		if r, err = triage(ctx, local, gh, reader, input, log); err != nil {
			return false, err
		}
		r.Branch, r.CreatedAt = reference, a.CreatedAt
		r.Located = verifiedClues(code, r).Location.Path != ""
		if r.Incomplete != nil {
			continue
		}
		// A failed duplicate search leaves the duplicates out of the comment rather than blocking it.
		duplicates, err := findDuplicates(ctx, path, reader, r, input, others, log)
		if err != nil {
			comparisonErr = err
			r.DuplicateSearchFailed = true
		} else {
			matches := report.Report{Duplicates: duplicates}
			if err := (report.Checker{Advisories: byID}).Verify(ctx, &matches); err != nil {
				return false, err
			}
			if err := confirmPrivateDuplicates(ctx, path, reader, eng, r, input, matches.Duplicates, byID, log); err != nil {
				comparisonErr = errors.Join(comparisonErr, err)
				privateNote += "\nPrivate exact duplicate confirmation could not complete.\n"
			}
			r.Duplicates = matches.Duplicates
		}
	}
	r.Provenance = fmt.Sprintf("\nRepository: `%s`. Advisory: `%s`. Input revision: `%s`.\n%s", cfg.Repo, a.GHSAID, revision, sources)
	body := report.Render(r)
	private := privateNote + report.RenderPrivate(r)
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
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return false, err
	}
	base := reportBase(cfg, a.GHSAID, revision)
	if keepAgentError(cfg, a.GHSAID, revision, r.Incomplete) != nil {
		log.Error("the agent error could not be kept in the private reports")
	}
	// A posted report closes the advisory, so a partial one is only posted by the last attempt.
	if r.Incomplete != nil && !final {
		log.Info("the report is incomplete, the advisory will be retried")
		if err := os.WriteFile(base+".md", []byte(private), 0o600); err != nil {
			return false, err
		}
		return false, errIncompleteReport
	}
	// Without its item, the next run triages the advisory again for the board.
	if b != nil {
		t := board.TriageOf(r)
		if err := b.Put(ctx, a, t.Priority(), &t, body); err != nil {
			if backfill {
				return true, err
			}
			log.Error("the project board could not be updated", "reason", describe(err))
		}
	}
	if backfill {
		if err := os.WriteFile(base+".md", []byte(private), 0o600); err != nil {
			return true, err
		}
		return true, comparisonErr
	}
	if err := os.WriteFile(base+".comment.md", []byte(body), 0o600); err != nil {
		return false, err
	}
	log.Info("posting the comment")
	if err := gh.PostComment(ctx, cfg.Repo, a.GHSAID, body); err != nil {
		return false, err
	}
	if err := os.WriteFile(base+".md", []byte(private), 0o600); err != nil {
		return true, err
	}
	return true, comparisonErr
}

// worktree checks a reference out next to the repository and shares its objects: only tamis reads it, the
// agent never does.
func worktree(ctx context.Context, repoPath, target, reference string) error {
	out, err := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "--verify", "--end-of-options", reference+"^{commit}").Output()
	if err != nil {
		return errors.New("resolving a configured source reference")
	}
	if err := exec.CommandContext(ctx, "git", "-C", repoPath, "worktree", "add", "--quiet", "--detach", "--", target, strings.TrimSpace(string(out))).Run(); err != nil {
		return errors.New("checking out a configured source reference")
	}

	return nil
}

// reportBase names the private files of one advisory revision, without the GHSA identifier.
func reportBase(cfg Config, ghsa, revision string) string {
	name := sha256.Sum256([]byte(ghsa))

	return filepath.Join(cfg.OutputDir, hex.EncodeToString(name[:])+"-"+revision)
}
