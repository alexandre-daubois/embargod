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

// ReadFile returns numbered lines of a file. os.Root refuses paths and symlinks escaping Dir.
func (r Repo) ReadFile(path string, start, end int) (string, error) {
	root, err := os.OpenRoot(r.Dir)
	if err != nil {
		return "", err
	}
	defer root.Close()

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

func (r Repo) Exists(path string) bool {
	root, err := os.OpenRoot(r.Dir)
	if err != nil {
		return false
	}
	defer root.Close()

	_, err = root.Stat(path)

	return err == nil
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

func (r Repo) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Dir}, args...)...)
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
