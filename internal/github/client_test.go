package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing token")
		}
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/security-advisories?after=x>; rel="next"`, c.BaseURL))
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
			return
		}
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-2"}]`)
	})

	got, err := c.ListAdvisories(context.Background(), "o/r", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GHSAID != "GHSA-1" || got[1].GHSAID != "GHSA-2" {
		t.Fatalf("got %+v", got)
	}
}

func TestListAdvisoriesFiltersState(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("state"); got != "triage" {
			t.Errorf("state = %q", got)
		}
		fmt.Fprint(w, `[]`)
	})

	if _, err := c.ListAdvisories(context.Background(), "o/r", "triage"); err != nil {
		t.Fatal(err)
	}
}

func TestPostComment(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/o/r/security-advisories/GHSA-1/comments" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["body"] != "hello" {
			t.Errorf("body = %v, %v", body, err)
		}
		w.WriteHeader(http.StatusCreated)
	})

	if err := c.PostComment(context.Background(), "o/r", "GHSA-1", "hello"); err != nil {
		t.Fatal(err)
	}
}

func TestSearchIssuesIsScopedToTheRepository(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "overflow is:pr repo:o/r" {
			t.Errorf("q = %q", got)
		}
		fmt.Fprint(w, `{"items":[{"number":3,"pull_request":{}}]}`)
	})

	got, err := c.SearchIssues(context.Background(), "o/r", "overflow is:pr")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PullRequest == nil {
		t.Fatalf("got %+v", got)
	}
}

func TestErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/issues/404" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	if _, err := c.GetIssue(context.Background(), "o/r", 404); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := c.GetIssue(context.Background(), "o/r", 1); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("want a server error, got %v", err)
	}
}
