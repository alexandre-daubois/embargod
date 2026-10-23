package modelproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type upstreamCall struct {
	method, path, apiKey, auth, cookie string
}

// setup returns a proxy for p, pointed at a fake upstream that records each call.
func setup(t *testing.T, p Provider, status int) (*httptest.Server, *[]upstreamCall, string) {
	t.Helper()
	var calls []upstreamCall
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, upstreamCall{r.Method, r.URL.Path, r.Header.Get("X-Api-Key"), r.Header.Get("Authorization"), r.Header.Get("Cookie")})
		if status == http.StatusFound {
			w.Header().Set("Location", "https://evil.example/")
		}
		w.Header().Set("Set-Cookie", "session=1")
		w.WriteHeader(status)
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)
	p.Upstream = up.URL

	mp, err := New(p, "real-key")
	if err != nil {
		t.Fatal(err)
	}
	token, revoke := mp.Issue()
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)
	t.Cleanup(revoke)

	return srv, &calls, token
}

func call(t *testing.T, srv *httptest.Server, method, path string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	return resp
}

func withKey(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	h.Set("Cookie", "secret=1")

	return h
}

func TestAnthropicSwapsTheToken(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)

	resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token))

	if resp.StatusCode != http.StatusOK || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("status %d, set-cookie %q", resp.StatusCode, resp.Header.Get("Set-Cookie"))
	}
	if len(*calls) != 1 {
		t.Fatalf("calls = %+v", *calls)
	}
	got := (*calls)[0]
	if got.path != "/v1/messages" || got.apiKey != "real-key" || got.auth != "" || got.cookie != "" {
		t.Fatalf("upstream got %+v", got)
	}
}

func TestOpenAISwapsTheBearerToken(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)

	resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+token))

	if resp.StatusCode != http.StatusOK || len(*calls) != 1 || (*calls)[0].auth != "Bearer real-key" || (*calls)[0].apiKey != "" {
		t.Fatalf("status %d, calls %+v", resp.StatusCode, *calls)
	}
}

func TestRefusals(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)

	for name, tc := range map[string]struct {
		method, path string
		header       http.Header
		status       int
	}{
		"no token":       {http.MethodPost, PathPrefix + "/v1/messages", http.Header{}, http.StatusUnauthorized},
		"unknown token":  {http.MethodPost, PathPrefix + "/v1/messages", withKey("X-Api-Key", "embargod-guess"), http.StatusUnauthorized},
		"real key":       {http.MethodPost, PathPrefix + "/v1/messages", withKey("X-Api-Key", "real-key"), http.StatusUnauthorized},
		"other route":    {http.MethodPost, PathPrefix + "/v1/files", withKey("X-Api-Key", token), http.StatusForbidden},
		"wrong method":   {http.MethodDelete, PathPrefix + "/v1/messages", withKey("X-Api-Key", token), http.StatusForbidden},
		"traversal":      {http.MethodPost, PathPrefix + "/v1/x/../messages", withKey("X-Api-Key", token), http.StatusForbidden},
		"encoded path":   {http.MethodPost, PathPrefix + "/v1/messages%2Fbatches", withKey("X-Api-Key", token), http.StatusForbidden},
		"nested model":   {http.MethodGet, PathPrefix + "/v1/models/a/b", withKey("X-Api-Key", token), http.StatusForbidden},
		"outside prefix": {http.MethodPost, "/v1/messages", withKey("X-Api-Key", token), http.StatusNotFound},
		"openai route":   {http.MethodPost, PathPrefix + "/v1/responses", withKey("X-Api-Key", token), http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			if resp := call(t, srv, tc.method, tc.path, tc.header); resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing should reach the upstream: %+v", *calls)
	}
}

func TestRevokedTokenIsRefused(t *testing.T) {
	mp, err := New(Anthropic, "real-key")
	if err != nil {
		t.Fatal(err)
	}
	token, revoke := mp.Issue()
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)

	revoke()

	if resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUpstreamRedirectIsNotRelayed(t *testing.T) {
	srv, _, token := setup(t, Anthropic, http.StatusFound)

	resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token))

	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Location") != "" {
		t.Fatalf("status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestNewRequiresAKey(t *testing.T) {
	if _, err := New(Anthropic, ""); err == nil {
		t.Fatal("want an error")
	}
}
