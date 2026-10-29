// Package github is a minimal REST client for the endpoints tamis needs.
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
	"slices"
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

// Unwrap also treats 410 as not found: GitHub answers it for an issue deleted from a repository the token can read.
func (e *HTTPError) Unwrap() error {
	if e.Status == http.StatusNotFound || e.Status == http.StatusGone {
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
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
}

type Issue struct {
	ID          int64     `json:"id"`
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
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

func (c *Client) GetAdvisory(ctx context.Context, repo, ghsa string) (Advisory, error) {
	var a Advisory
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/security-advisories/%s", c.BaseURL, repo, url.PathEscape(ghsa)), nil, &a)
	return a, err
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

type Project struct {
	Public bool `json:"public"`
}

type ProjectField struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	DataType string `json:"data_type"`
	Options  []struct {
		ID   string `json:"id"`
		Name struct {
			Raw string `json:"raw"`
		} `json:"name"`
	} `json:"options"`
}

// ProjectItem holds the values of the fields it was listed with. A text value is {"raw": ...}, a single select
// value {"name": {"raw": ...}} and a number a bare number.
type ProjectItem struct {
	ID int64 `json:"id"`
	// ContentType is "DraftIssue" or "Issue". Only GraphQL can edit a draft, by its node ID.
	ContentType string `json:"content_type"`
	Content     struct {
		NodeID string `json:"node_id"`
		ID     int64  `json:"id"`
		Number int    `json:"number"`
		Body   string `json:"body"`
	} `json:"content"`
	Fields []struct {
		ID    int64           `json:"id"`
		Value json.RawMessage `json:"value"`
	} `json:"fields"`
}

// FieldValue sets a text, number or date field, or a single select field by its option ID.
type FieldValue struct {
	ID    int64 `json:"id"`
	Value any   `json:"value"`
}

func (c *Client) GetProject(ctx context.Context, org string, number int) (Project, error) {
	var p Project
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/orgs/%s/projectsV2/%d", c.BaseURL, url.PathEscape(org), number), nil, &p)

	return p, err
}

func (c *Client) ListProjectFields(ctx context.Context, org string, number int) ([]ProjectField, error) {
	return list[ProjectField](ctx, c, fmt.Sprintf("%s/orgs/%s/projectsV2/%d/fields?per_page=100", c.BaseURL, url.PathEscape(org), number))
}

// itemsQuery lists the items of a project. The REST listing leaves out, for an App token, the items that are
// issues of a private repository.
const itemsQuery = `query($org: String!, $number: Int!, $after: String) {
  organization(login: $org) { projectV2(number: $number) { items(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      databaseId type
      content { ... on DraftIssue { id } ... on Issue { databaseId number body } }
      fieldValues(first: 50) { nodes {
        ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { databaseId } } }
        ... on ProjectV2ItemFieldNumberValue { number field { ... on ProjectV2FieldCommon { databaseId } } }
        ... on ProjectV2ItemFieldDateValue { date field { ... on ProjectV2FieldCommon { databaseId } } }
        ... on ProjectV2ItemFieldSingleSelectValue { name optionId field { ... on ProjectV2FieldCommon { databaseId } } }
      } }
    }
  } } }
}`

// ListProjectItems returns the items of a project with the values of the given fields, in the shape of the REST
// API: {"raw": ...} for a text, {"id": ..., "name": {"raw": ...}} for a single select, the bare value otherwise.
func (c *Client) ListProjectItems(ctx context.Context, org string, number int, fields []int64) ([]ProjectItem, error) {
	type value struct {
		Text     *string  `json:"text"`
		Number   *float64 `json:"number"`
		Date     *string  `json:"date"`
		Name     *string  `json:"name"`
		OptionID string   `json:"optionId"`
		Field    struct {
			DatabaseID int64 `json:"databaseId"`
		} `json:"field"`
	}
	var items []ProjectItem
	var after *string
	for {
		var out struct {
			Data struct {
				Organization struct {
					ProjectV2 struct {
						Items struct {
							PageInfo struct {
								HasNextPage bool   `json:"hasNextPage"`
								EndCursor   string `json:"endCursor"`
							} `json:"pageInfo"`
							Nodes []struct {
								DatabaseID int64  `json:"databaseId"`
								Type       string `json:"type"`
								Content    struct {
									ID         string `json:"id"`
									DatabaseID int64  `json:"databaseId"`
									Number     int    `json:"number"`
									Body       string `json:"body"`
								} `json:"content"`
								FieldValues struct {
									Nodes []value `json:"nodes"`
								} `json:"fieldValues"`
							} `json:"nodes"`
						} `json:"items"`
					} `json:"projectV2"`
				} `json:"organization"`
			} `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if _, err := c.do(ctx, http.MethodPost, c.BaseURL+"/graphql", map[string]any{"query": itemsQuery, "variables": map[string]any{"org": org, "number": number, "after": after}}, &out); err != nil {
			return nil, err
		}
		if len(out.Errors) > 0 {
			return nil, errors.New("github: GraphQL request failed")
		}
		page := out.Data.Organization.ProjectV2.Items
		for _, n := range page.Nodes {
			item := ProjectItem{ID: n.DatabaseID, ContentType: "DraftIssue"}
			item.Content.NodeID = n.Content.ID
			if n.Type == "ISSUE" {
				item.ContentType, item.Content.ID, item.Content.Number, item.Content.Body = "Issue", n.Content.DatabaseID, n.Content.Number, n.Content.Body
			}
			for _, v := range n.FieldValues.Nodes {
				if !slices.Contains(fields, v.Field.DatabaseID) {
					continue
				}
				var raw any
				switch {
				case v.Text != nil:
					raw = map[string]string{"raw": *v.Text}
				case v.Name != nil:
					raw = map[string]any{"id": v.OptionID, "name": map[string]string{"raw": *v.Name}}
				case v.Number != nil:
					raw = *v.Number
				case v.Date != nil:
					raw = *v.Date
				default:
					continue
				}
				b, _ := json.Marshal(raw)
				item.Fields = append(item.Fields, struct {
					ID    int64           `json:"id"`
					Value json.RawMessage `json:"value"`
				}{v.Field.DatabaseID, b})
			}
			items = append(items, item)
		}
		if !page.PageInfo.HasNextPage {
			return items, nil
		}
		after = &page.PageInfo.EndCursor
	}
}

func (c *Client) CreateDraft(ctx context.Context, org string, number int, title, body string) (ProjectItem, error) {
	var item ProjectItem
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/orgs/%s/projectsV2/%d/drafts", c.BaseURL, url.PathEscape(org), number), map[string]string{"title": title, "body": body}, &item)

	return item, err
}

// UpdateDraft replaces the body of a draft issue, which the REST API cannot edit.
func (c *Client) UpdateDraft(ctx context.Context, draft, body string) error {
	var out struct {
		Errors []json.RawMessage `json:"errors"`
	}
	_, err := c.do(ctx, http.MethodPost, c.BaseURL+"/graphql", map[string]any{
		"query":     "mutation($id: ID!, $body: String!) { updateProjectV2DraftIssue(input: {draftIssueId: $id, body: $body}) { clientMutationId } }",
		"variables": map[string]string{"id": draft, "body": body},
	}, &out)
	// GraphQL reports its errors with a 200, and their messages may echo the body.
	if err == nil && len(out.Errors) > 0 {
		return errors.New("github: GraphQL request failed")
	}

	return err
}

func (c *Client) UpdateProjectItem(ctx context.Context, org string, number int, item int64, fields []FieldValue) error {
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/orgs/%s/projectsV2/%d/items/%d", c.BaseURL, url.PathEscape(org), number, item), map[string]any{"fields": fields}, nil)

	return err
}

type Repository struct {
	Private bool `json:"private"`
}

// InstallationRepositories names the repositories a GitHub App installation token reaches. Other tokens get an
// error.
func (c *Client) InstallationRepositories(ctx context.Context) ([]string, error) {
	var out struct {
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if _, err := c.do(ctx, http.MethodGet, c.BaseURL+"/installation/repositories?per_page=100", nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, len(out.Repositories))
	for i, r := range out.Repositories {
		names[i] = r.FullName
	}

	return names, nil
}

func (c *Client) GetRepository(ctx context.Context, repo string) (Repository, error) {
	var r Repository
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s", c.BaseURL, repo), nil, &r)

	return r, err
}

// ListIssues returns every issue of repo, open or closed, and its pull requests.
func (c *Client) ListIssues(ctx context.Context, repo string) ([]Issue, error) {
	return list[Issue](ctx, c, fmt.Sprintf("%s/repos/%s/issues?state=all&per_page=100", c.BaseURL, repo))
}

func (c *Client) CreateIssue(ctx context.Context, repo, title, body string) (Issue, error) {
	var i Issue
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/issues", c.BaseURL, repo), map[string]string{"title": title, "body": body}, &i)

	return i, err
}

// UpdateIssue sets the given fields of an issue, such as "body", "state" or "state_reason".
func (c *Client) UpdateIssue(ctx context.Context, repo string, number int, fields map[string]string) error {
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/repos/%s/issues/%d", c.BaseURL, repo, number), fields, nil)

	return err
}

// AddSubIssue makes the issue child a sub-issue of parent, moving it from any other parent.
func (c *Client) AddSubIssue(ctx context.Context, repo string, parent int, child int64) error {
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/issues/%d/sub_issues", c.BaseURL, repo, parent), map[string]any{"sub_issue_id": child, "replace_parent": true}, nil)

	return err
}

func (c *Client) AddProjectIssue(ctx context.Context, org string, number int, issue int64) (ProjectItem, error) {
	var item ProjectItem
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/orgs/%s/projectsV2/%d/items", c.BaseURL, url.PathEscape(org), number), map[string]any{"type": "Issue", "id": issue}, &item)

	return item, err
}

func (c *Client) GetIssue(ctx context.Context, repo string, number int) (Issue, error) {
	var i Issue
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/issues/%d", c.BaseURL, repo, number), nil, &i)

	return i, err
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
