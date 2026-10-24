// Package repo gives read-only access to the checked-out repository.
package repo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	maxFileLines = 400
	maxGrepLines = 200
)

type Repo struct {
	Dir string
}

var errNotTracked = errors.New("not a file tracked by git")

// ReadFile returns numbered lines of a tracked file.
func (r Repo) ReadFile(path string, start, end int) (string, error) {
	if !r.tracked(path) {
		return "", errNotTracked
	}

	root, err := os.OpenRoot(r.Dir)
	if err != nil {
		return "", err
	}
	defer root.Close()

	// A tracked symlink could point inside .git, where actions/checkout may persist a token.
	if info, err := root.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", errNotTracked
	}
	data, err := root.ReadFile(path)
	if err != nil {
		return "", err
	}

	start = max(start, 1)
	if end < start || end-start >= maxFileLines {
		end = start + maxFileLines - 1
	}

	var b strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan() && n <= end; n++ {
		if n >= start {
			fmt.Fprintf(&b, "%d\t%s\n", n, sc.Text())
		}
	}

	return b.String(), sc.Err()
}

// Exists reports whether path is a tracked file or a directory holding tracked files.
func (r Repo) Exists(path string) bool {
	return r.tracked(path)
}

// tracked keeps the model on the repository content: untracked files include .git and whatever other steps wrote.
func (r Repo) tracked(path string) bool {
	if path == "" {
		return false
	}
	out, err := r.git("ls-files", "--", path)

	return err == nil && out != ""
}

// Files lists the tracked files.
func (r Repo) Files() ([]string, error) {
	out, err := r.git("ls-files", "-z")
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSuffix(out, "\x00"), "\x00"), nil
}

// Grep runs an extended regexp search over tracked files, path narrows it when set.
func (r Repo) Grep(pattern, path string) (string, error) {
	args := []string{"grep", "-n", "-I", "-E", "-e", pattern}
	if path != "" {
		args = append(args, "--", path)
	}

	out, err := r.git(args...)
	if isNoMatch(err) {
		return "no match", nil
	}
	if err != nil {
		return "", err
	}

	return truncateLines(out, maxGrepLines), nil
}

// HasSymbol reports whether symbol appears as a whole word in path, or anywhere when path is empty.
func (r Repo) HasSymbol(path, symbol string) (bool, error) {
	args := []string{"grep", "-q", "-F", "-w", "-e", symbol}
	if path != "" {
		args = append(args, "--", path)
	}

	_, err := r.git(args...)
	if isNoMatch(err) {
		return false, nil
	}

	return err == nil, err
}

func (r Repo) Log(path, grep string) (string, error) {
	args := []string{"log", "-n", "30", "--date=short", "--format=%h %ad %s"}
	if grep != "" {
		args = append(args, "--regexp-ignore-case", "--grep="+grep)
	}
	if path != "" {
		args = append(args, "--", path)
	}

	return r.git(args...)
}

// Head returns the checked-out commit and its branch, empty when HEAD is detached.
func (r Repo) Head() (commit, branch string, err error) {
	out, err := r.git("rev-parse", "HEAD", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", "", err
	}
	commit, branch, _ = strings.Cut(strings.TrimSpace(out), "\n")
	if branch == "HEAD" {
		branch = ""
	}

	return commit, branch, nil
}

// Lines returns the lines of path at HEAD, and false when path is not a file there.
func (r Repo) Lines(path string) ([]string, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	if kind, err := r.git("cat-file", "-t", "HEAD:"+path); err != nil || strings.TrimSpace(kind) != "blob" {
		return nil, false, nil
	}
	out, err := r.git("cat-file", "blob", "HEAD:"+path)
	if err != nil {
		return nil, false, err
	}

	return strings.Split(strings.TrimSuffix(out, "\n"), "\n"), true, nil
}

// LastChange returns the latest commit that added or removed text in path, with its date, empty when none did.
func (r Repo) LastChange(path, text string) (commit, date string, err error) {
	out, err := r.git("log", "-n", "1", "--date=short", "--format=%H %ad", "-S"+text, "HEAD", "--", path)
	if err != nil {
		return "", "", err
	}
	commit, date, _ = strings.Cut(strings.TrimSpace(out), " ")

	return commit, date, nil
}

func (r Repo) git(args ...string) (string, error) {
	// Literal pathspecs stop paths like ":(glob)**" from being read as patterns.
	cmd := exec.Command("git", append([]string{"-C", r.Dir, "--literal-pathspecs"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil && stderr.Len() > 0 {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}

	return string(out), err
}

// git grep exits with 1 when nothing matches and with 128 on errors.
func isNoMatch(err error) bool {
	var exit *exec.ExitError

	return errors.As(err, &exit) && exit.ExitCode() == 1
}

func truncateLines(s string, n int) string {
	lines := strings.SplitAfter(s, "\n")
	if len(lines) <= n {
		return s
	}

	return strings.Join(lines[:n], "") + fmt.Sprintf("... %d more lines, narrow the search\n", len(lines)-n)
}
