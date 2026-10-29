package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
}

func TestListAdvisoriesFollowsPagination(t *testing.T) {
	var c *Client
	c = newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"), "missing token")
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/security-advisories?after=x>; rel="next"`, c.BaseURL))
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
			return
		}
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-2"}]`)
	})

	got, err := c.ListAdvisories(context.Background(), "o/r", "")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "GHSA-1", got[0].GHSAID)
	require.Equal(t, "GHSA-2", got[1].GHSAID)
}

func TestListAdvisoriesFiltersState(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "triage", r.URL.Query().Get("state"))
		fmt.Fprint(w, `[]`)
	})

	_, err := c.ListAdvisories(context.Background(), "o/r", "triage")
	require.NoError(t, err)
}

func TestPostComment(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/repos/o/r/security-advisories/GHSA-1/comments", r.URL.Path)
		var body map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "hello", body["body"])
		w.WriteHeader(http.StatusCreated)
	})

	require.NoError(t, c.PostComment(context.Background(), "o/r", "GHSA-1", "hello"))
}

func TestProjectItems(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /orgs/php/projectsV2/16":
			fmt.Fprint(w, `{"id":1,"number":16,"public":true}`)
		case "GET /orgs/php/projectsV2/16/items":
			assert.Equal(t, "1,2", r.URL.Query().Get("fields"))
			fmt.Fprint(w, `[{"id":5,"content":{"node_id":"DI_5"},"fields":[{"id":1,"value":{"raw":"GHSA-1"}}]}]`)
		case "POST /orgs/php/projectsV2/16/drafts":
			var body map[string]string
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, map[string]string{"title": "t", "body": "b"}, body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":6,"content":{"node_id":"DI_6"}}`)
		case "PATCH /orgs/php/projectsV2/16/items/6":
			var body map[string][]map[string]any
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, []map[string]any{{"id": float64(1), "value": "GHSA-1"}, {"id": float64(2), "value": nil}}, body["fields"])
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	project, err := c.GetProject(context.Background(), "php", 16)
	require.NoError(t, err)
	require.True(t, project.Public)
	items, err := c.ListProjectItems(context.Background(), "php", 16, []int64{1, 2})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, int64(5), items[0].ID)
	require.JSONEq(t, `{"raw":"GHSA-1"}`, string(items[0].Fields[0].Value))
	require.Equal(t, "DI_5", items[0].Content.NodeID)
	draft, err := c.CreateDraft(context.Background(), "php", 16, "t", "b")
	require.NoError(t, err)
	require.Equal(t, int64(6), draft.ID)
	require.Equal(t, "DI_6", draft.Content.NodeID)
	require.NoError(t, c.UpdateProjectItem(context.Background(), "php", 16, 6, []FieldValue{{ID: 1, Value: "GHSA-1"}, {ID: 2}}))
}

func TestUpdateDraft(t *testing.T) {
	for name, tc := range map[string]struct {
		response string
		err      bool
	}{
		"updated":        {`{"data":{"updateProjectV2DraftIssue":{"clientMutationId":null}}}`, false},
		"graphql errors": {`{"errors":[{"message":"SECRET-PAYLOAD"}]}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST /graphql", r.Method+" "+r.URL.Path)
				var body struct {
					Query     string            `json:"query"`
					Variables map[string]string `json:"variables"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Contains(t, body.Query, "updateProjectV2DraftIssue")
				assert.Equal(t, map[string]string{"id": "DI_6", "body": "b"}, body.Variables)
				fmt.Fprint(w, tc.response)
			})

			err := c.UpdateDraft(context.Background(), "DI_6", "b")

			require.Equal(t, tc.err, err != nil, "%v", err)
			if err != nil {
				require.NotContains(t, err.Error(), "SECRET-PAYLOAD")
			}
		})
	}
}

func TestIssues(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/php/php-src-security":
			fmt.Fprint(w, `{"private":true}`)
		case "GET /repos/php/php-src-security/issues":
			assert.Equal(t, "all", r.URL.Query().Get("state"), "closed issues would be created again")
			fmt.Fprint(w, `[{"id":42,"number":7,"body":"b"}]`)
		case "POST /repos/php/php-src-security/issues":
			assert.Equal(t, map[string]any{"title": "t", "body": "b"}, body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":42,"number":7}`)
		case "PATCH /repos/php/php-src-security/issues/7":
			assert.Equal(t, map[string]any{"state": "closed", "state_reason": "completed"}, body)
		case "POST /repos/php/php-src-security/issues/3/sub_issues":
			assert.Equal(t, map[string]any{"sub_issue_id": float64(42), "replace_parent": true}, body)
			w.WriteHeader(http.StatusCreated)
		case "POST /orgs/php/projectsV2/16/items":
			assert.Equal(t, map[string]any{"type": "Issue", "id": float64(42)}, body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":9,"content_type":"Issue"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	repo, err := c.GetRepository(context.Background(), "php/php-src-security")
	require.NoError(t, err)
	require.True(t, repo.Private)
	issues, err := c.ListIssues(context.Background(), "php/php-src-security")
	require.NoError(t, err)
	require.Equal(t, []Issue{{ID: 42, Number: 7, Body: "b"}}, issues)
	issue, err := c.CreateIssue(context.Background(), "php/php-src-security", "t", "b")
	require.NoError(t, err)
	require.Equal(t, int64(42), issue.ID)
	require.Equal(t, 7, issue.Number)
	require.NoError(t, c.UpdateIssue(context.Background(), "php/php-src-security", 7, map[string]string{"state": "closed", "state_reason": "completed"}))
	require.NoError(t, c.AddSubIssue(context.Background(), "php/php-src-security", 3, 42))
	item, err := c.AddProjectIssue(context.Background(), "php", 16, 42)
	require.NoError(t, err)
	require.Equal(t, int64(9), item.ID)
	require.Equal(t, "Issue", item.ContentType)
}

func TestProjectErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	_, err := c.CreateDraft(context.Background(), "php", 16, "t", "b")
	require.Error(t, c.UpdateDraft(context.Background(), "DI_6", "b"))
	_, err = c.GetRepository(context.Background(), "php/php-src-security")
	require.Error(t, err)
	_, err = c.CreateIssue(context.Background(), "php/php-src-security", "t", "b")
	require.Error(t, err)
	require.Error(t, c.AddSubIssue(context.Background(), "php/php-src-security", 3, 42))
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusForbidden, httpErr.Status)
	require.Error(t, c.UpdateProjectItem(context.Background(), "php", 16, 6, nil))
	_, err = c.ListProjectFields(context.Background(), "php", 16)
	require.Error(t, err)
	_, err = c.GetProject(context.Background(), "php", 16)
	require.Error(t, err)
}

func TestErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/issues/404" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, `{"message":"SECRET-PAYLOAD"}`, http.StatusUnprocessableEntity)
	})

	_, err := c.GetIssue(context.Background(), "o/r", 404)
	require.ErrorIs(t, err, ErrNotFound)
	err = c.PostComment(context.Background(), "o/r", "GHSA-secret-id", "SECRET-PAYLOAD")
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusUnprocessableEntity, httpErr.Status)
	require.NotErrorIs(t, err, ErrNotFound)
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD", "the body or the advisory leaked")
	require.NotContains(t, err.Error(), "GHSA-secret-id", "the body or the advisory leaked")
}

func TestNetworkErrorsDoNotLeakTheURL(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "tok", HTTP: http.DefaultClient}

	_, err := c.ListComments(context.Background(), "o/r", "GHSA-secret-id")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "GHSA-secret-id")
}

func TestPaginationStaysOnTheAPIHost(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Link", `<https://evil.example/steal?after=x>; rel="next"`)
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
	})

	got, err := c.ListAdvisories(context.Background(), "o/r", "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 1, calls)
}

func TestLogin(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user", r.URL.Path)
		fmt.Fprint(w, `{"login":"tamis-bot"}`)
	})

	got, err := c.Login(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tamis-bot", got)
}

func TestInvalidJSONResponse(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"number": "SECRET-PAYLOAD"`)
	})

	_, err := c.GetIssue(context.Background(), "o/r", 1)
	require.EqualError(t, err, "github: invalid response")
}

func TestNew(t *testing.T) {
	c := New("tok")

	require.Equal(t, "https://api.github.com", c.BaseURL)
	require.Equal(t, "tok", c.Token)
	require.Positive(t, c.HTTP.Timeout)
}

func TestGetAdvisoryReadsTheCurrentReportAndReporter(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/repos/o/r/security-advisories/GHSA-1", r.URL.Path)
		fmt.Fprint(w, `{"ghsa_id":"GHSA-1","description":"current revision","author":{"login":"reporter"}}`)
	})
	a, err := c.GetAdvisory(t.Context(), "o/r", "GHSA-1")
	require.NoError(t, err)
	require.Equal(t, "current revision", a.Description)
	require.Equal(t, "reporter", a.Author.Login)
	c = newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	_, err = c.GetAdvisory(t.Context(), "o/r", "missing")
	require.ErrorIs(t, err, ErrNotFound, "missing advisory accepted")
}

func TestHTTPErrorUnwrapsOnlyNotFoundAndGone(t *testing.T) {
	require.ErrorIs(t, &HTTPError{Status: 404}, ErrNotFound, "only a 404 or a 410 is ErrNotFound")
	require.ErrorIs(t, &HTTPError{Status: 410}, ErrNotFound, "only a 404 or a 410 is ErrNotFound")
	require.NotErrorIs(t, &HTTPError{Status: 403}, ErrNotFound, "only a 404 or a 410 is ErrNotFound")
	require.NotErrorIs(t, &HTTPError{}, ErrNotFound, "only a 404 or a 410 is ErrNotFound")
}
