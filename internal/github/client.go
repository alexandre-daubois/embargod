// Package github is a minimal REST client for the endpoints embargod needs.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")

// HTTPError keeps only the status code: paths name advisories and bodies may echo content.
type HTTPError struct {
	Status int
}

func (e *HTTPError) Error() string {
	if e.Status == 0 {
		return "github: request failed"
	}

	return fmt.Sprintf("github: HTTP %d", e.Status)
}

func (e *HTTPError) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return ErrNotFound
	}

	return nil
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

type Advisory struct {
	GHSAID      string    `json:"ghsa_id"`
	HTMLURL     string    `json:"html_url"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	State       string    `json:"state"`
	Severity    string    `json:"severity"`
	CWEIDs      []string  `json:"cwe_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

type Issue struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	State       string    `json:"state"`
	HTMLURL     string    `json:"html_url"`
	PullRequest *struct{} `json:"pull_request"`
}

type Comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(token string) *Client {
	return &Client{BaseURL: "https://api.github.com", Token: token, HTTP: &http.Client{Timeout: time.Minute}}
}

// Login returns the login of the account owning the token.
func (c *Client) Login(ctx context.Context) (string, error) {
	var user struct {
		Login string `json:"login"`
	}
	_, err := c.do(ctx, http.MethodGet, c.BaseURL+"/user", nil, &user)

	return user.Login, err
}

// ListAdvisories returns the repository advisories, all states when state is empty.
func (c *Client) ListAdvisories(ctx context.Context, repo, state string) ([]Advisory, error) {
	q := url.Values{"per_page": {"100"}}
	if state != "" {
		q.Set("state", state)
	}

	return list[Advisory](ctx, c, fmt.Sprintf("%s/repos/%s/security-advisories?%s", c.BaseURL, repo, q.Encode()))
}

// ListComments relies on the advisory comments API, in public preview since 2026-10-02.
func (c *Client) ListComments(ctx context.Context, repo, ghsa string) ([]Comment, error) {
	return list[Comment](ctx, c, fmt.Sprintf("%s/repos/%s/security-advisories/%s/comments?per_page=100", c.BaseURL, repo, url.PathEscape(ghsa)))
}

func (c *Client) PostComment(ctx context.Context, repo, ghsa, body string) error {
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/security-advisories/%s/comments", c.BaseURL, repo, url.PathEscape(ghsa)), map[string]string{"body": body}, nil)

	return err
}

func (c *Client) GetIssue(ctx context.Context, repo string, number int) (Issue, error) {
	var i Issue
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/issues/%d", c.BaseURL, repo, number), nil, &i)

	return i, err
}

// SearchIssues searches issues and pull requests, always scoped to repo.
func (c *Client) SearchIssues(ctx context.Context, repo, query string) ([]Issue, error) {
	q := url.Values{"q": {query + " repo:" + repo}, "per_page": {"20"}}
	var res struct {
		Items []Issue `json:"items"`
	}
	_, err := c.do(ctx, http.MethodGet, c.BaseURL+"/search/issues?"+q.Encode(), nil, &res)

	return res.Items, err
}

// list fetches every page by following the Link header.
func list[T any](ctx context.Context, c *Client, next string) ([]T, error) {
	var all []T
	for next != "" {
		var page []T
		resp, err := c.do(ctx, http.MethodGet, next, nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		next = ""
		// The token goes with every request, so pagination never leaves the API host.
		if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil && strings.HasPrefix(m[1], c.BaseURL+"/") {
			next = m[1]
		}
	}

	return all, nil
}

func (c *Client) do(ctx context.Context, method, u string, body, out any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &HTTPError{}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return resp, &HTTPError{Status: resp.StatusCode}
	}
	if out == nil {
		return resp, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp, errors.New("github: invalid response")
	}

	return resp, nil
}
