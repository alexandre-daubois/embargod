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
