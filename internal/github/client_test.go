package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
		http.Error(w, `{"message":"SECRET-PAYLOAD"}`, http.StatusUnprocessableEntity)
	})

	if _, err := c.GetIssue(context.Background(), "o/r", 404); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	err := c.PostComment(context.Background(), "o/r", "GHSA-secret-id", "SECRET-PAYLOAD")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusUnprocessableEntity || errors.Is(err, ErrNotFound) {
		t.Fatalf("want an HTTP 422, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-PAYLOAD") || strings.Contains(err.Error(), "GHSA-secret-id") {
		t.Fatalf("the body or the advisory leaked: %v", err)
	}
}

func TestNetworkErrorsDoNotLeakTheURL(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "tok", HTTP: http.DefaultClient}

	_, err := c.ListComments(context.Background(), "o/r", "GHSA-secret-id")
	if err == nil || strings.Contains(err.Error(), "GHSA-secret-id") {
		t.Fatalf("want an error without the advisory, got %v", err)
	}
}

func TestPaginationStaysOnTheAPIHost(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Link", `<https://evil.example/steal?after=x>; rel="next"`)
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
	})

	got, err := c.ListAdvisories(context.Background(), "o/r", "")
	if err != nil || len(got) != 1 || calls != 1 {
		t.Fatalf("got %v, %v after %d calls", got, err, calls)
	}
}

func TestLogin(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"login":"embargod-bot"}`)
	})

	if got, err := c.Login(context.Background()); err != nil || got != "embargod-bot" {
		t.Fatalf("got %q, %v", got, err)
	}
}
