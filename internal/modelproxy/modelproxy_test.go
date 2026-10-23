package modelproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type upstreamCall struct {
	method, path, apiKey, auth, cookie, accountID, body string
}

// setup returns a proxy for p, pointed at a fake upstream that records each call.
func setup(t *testing.T, p Provider, status int) (*httptest.Server, *[]upstreamCall, string) {
	t.Helper()
	var calls []upstreamCall
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, upstreamCall{r.Method, r.URL.Path, r.Header.Get("X-Api-Key"), r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("ChatGPT-Account-Id"), string(body)})
		if status == http.StatusFound {
			w.Header().Set("Location", "https://evil.example/")
		}
		w.Header().Set("Set-Cookie", "session=1")
		w.WriteHeader(status)
		response := `{"ok":true}`
		if strings.HasSuffix(r.URL.Path, "/v1/user-auth-credential/whoami") {
			response = `{"email":"security@example.com","chatgpt_user_id":"user-secret","chatgpt_account_id":"account-secret","chatgpt_plan_type":"enterprise","chatgpt_account_is_fedramp":false}`
		}
		if strings.HasSuffix(r.URL.Path, "/wham/config/bundle") {
			response = `{"config_toml":{"enterprise_managed":[{"id":"secret","name":"secret","contents":"additional_developer_instructions = \\"internal\\""}]}}`
		}
		io.WriteString(w, response)
	}))
	t.Cleanup(up.Close)
	p.Upstream = up.URL
	upstreams := map[string]string{}
	for prefix, raw := range p.Upstreams {
		u, _ := url.Parse(raw)
		upstreams[prefix] = up.URL + u.Path
	}
	if p.Upstreams != nil {
		p.Upstreams = upstreams
	}

	mp, err := New(p, "real-key", "allowed")
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
	return callBody(t, srv, method, path, `{"model":"allowed"}`, header)
}

func callBody(t *testing.T, srv *httptest.Server, method, path, body string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
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

	resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages?beta=true", withKey("X-Api-Key", token))

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
	if !strings.Contains((*calls)[0].body, `"store":false`) || !strings.Contains((*calls)[0].body, `"background":false`) {
		t.Fatalf("unsafe OpenAI defaults were not overridden: %s", (*calls)[0].body)
	}
}

func TestChatGPTSwapsTheAccessTokenOnBothUpstreams(t *testing.T) {
	srv, calls, token := setup(t, ChatGPT, http.StatusOK)
	if !strings.HasPrefix(token, "at-embargod-") {
		t.Fatalf("Codex only reads a token starting with at- as an access token: %q", token)
	}

	whoami := call(t, srv, http.MethodGet, PathPrefix+"/auth/v1/user-auth-credential/whoami", withKey("Authorization", "Bearer "+token))
	identity, _ := io.ReadAll(whoami.Body)
	backendKey := withKey("Authorization", "Bearer "+token)
	backendKey.Set("ChatGPT-Account-Id", "attacker-controlled")
	bundle := call(t, srv, http.MethodGet, PathPrefix+"/backend-api/wham/config/bundle", backendKey)
	managed, _ := io.ReadAll(bundle.Body)
	responses := call(t, srv, http.MethodPost, PathPrefix+"/backend-api/codex/responses", backendKey)

	if whoami.StatusCode != http.StatusOK || bundle.StatusCode != http.StatusOK || responses.StatusCode != http.StatusOK || len(*calls) != 3 {
		t.Fatalf("statuses %d, %d and %d, calls %+v", whoami.StatusCode, bundle.StatusCode, responses.StatusCode, *calls)
	}
	for i, want := range []string{"/api/accounts/v1/user-auth-credential/whoami", "/backend-api/wham/config/bundle", "/backend-api/codex/responses"} {
		if got := (*calls)[i]; got.path != want || got.auth != "Bearer real-key" || got.cookie != "" {
			t.Errorf("upstream got %+v, want path %s", got, want)
		}
	}
	if (*calls)[0].accountID != "" || (*calls)[1].accountID != "account-secret" || (*calls)[2].accountID != "account-secret" {
		t.Errorf("workspace identity was not applied server-side only: %+v", *calls)
	}
	if strings.Contains(string(identity), "secret") || strings.Contains(string(identity), "security@example.com") || !strings.Contains(string(identity), `"chatgpt_account_id":"embargod"`) || strings.Contains(string(managed), "internal") || !strings.Contains(string(managed), `"enterprise_managed":[]`) {
		t.Errorf("private workspace response reached the agent: identity %s, bundle %s", identity, managed)
	}
	if body := (*calls)[2].body; !strings.Contains(body, `"store":false`) || strings.Contains(body, "background") || strings.Contains(body, "max_output_tokens") {
		t.Errorf("the ChatGPT backend only accepts store set to false: %s", body)
	}
}

func TestChatGPTRefusesAnIdentityWithoutAccount(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"email":"security@example.com","chatgpt_plan_type":"enterprise"}`)
	}))
	t.Cleanup(up.Close)
	p := ChatGPT
	p.Upstreams = map[string]string{"/auth": up.URL + "/api/accounts", "/backend-api": up.URL + "/backend-api"}
	mp, err := New(p, "real-key", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	token, revoke := mp.Issue()
	t.Cleanup(revoke)
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)

	resp := call(t, srv, http.MethodGet, PathPrefix+"/auth/v1/user-auth-credential/whoami", withKey("Authorization", "Bearer "+token))
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "security@example.com") {
		t.Fatalf("status %d, body %s", resp.StatusCode, body)
	}
}

func TestChatGPTRefusesTheOtherBackendRoutes(t *testing.T) {
	srv, calls, token := setup(t, ChatGPT, http.StatusOK)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/backend-api/codex/models"},
		{http.MethodGet, "/backend-api/wham/accounts/check"},
		{http.MethodPost, "/backend-api/ps/mcp"},
		{http.MethodPost, "/auth/v1/user-auth-credential/whoami"},
		{http.MethodGet, "/backend-api/codex/responses"},
		{http.MethodPost, "/v1/responses"},
	} {
		if resp := call(t, srv, tc.method, PathPrefix+tc.path, withKey("Authorization", "Bearer "+token)); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: status %d", tc.method, tc.path, resp.StatusCode)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("refused routes reached the upstream: %+v", *calls)
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
		"query":          {http.MethodPost, PathPrefix + "/v1/messages?feature=remote", withKey("X-Api-Key", token), http.StatusForbidden},
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
	mp, err := New(Anthropic, "real-key", "allowed")
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
	if _, err := New(Anthropic, "", "allowed"); err == nil {
		t.Fatal("want an error")
	}
}

func TestNewRequiresAModel(t *testing.T) {
	if _, err := New(Anthropic, "real-key", ""); err == nil {
		t.Fatal("want an error")
	}
}

func TestProviderCapabilitiesAndOtherModelsAreRefused(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	for name, body := range map[string]string{
		"other model":  `{"model":"expensive"}`,
		"remote MCP":   `{"model":"allowed","tools":[{"type":"mcp","server_url":"https://evil.example"}]}`,
		"remote file":  `{"model":"allowed","input":[{"type":"input_file","file_url":"https://evil.example"}]}`,
		"conversation": `{"model":"allowed","conversation":"conv_other"}`,
		"untyped tool": `{"model":"allowed","tools":[{"name":"remote"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token)); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing should reach the upstream: %+v", *calls)
	}
}

func TestProviderTokenLimitIsClamped(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", `{"model":"allowed","max_output_tokens":16001}`, withKey("Authorization", "Bearer "+token))
	if resp.StatusCode != http.StatusOK || len(*calls) != 1 || !strings.Contains((*calls)[0].body, `"max_output_tokens":16000`) {
		t.Fatalf("status %d, calls %+v", resp.StatusCode, *calls)
	}
}

func TestEveryAccessTokenRequestSpendsTheQuota(t *testing.T) {
	srv, calls, token := setup(t, ChatGPT, http.StatusOK)
	whoami := PathPrefix + "/auth/v1/user-auth-credential/whoami"
	for range maxRequests {
		call(t, srv, http.MethodGet, whoami, withKey("Authorization", "Bearer "+token))
	}
	if resp := call(t, srv, http.MethodPost, PathPrefix+"/backend-api/codex/responses", withKey("Authorization", "Bearer "+token)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request after token checks: status %d", resp.StatusCode)
	}
	if resp := call(t, srv, http.MethodGet, whoami, withKey("Authorization", "Bearer at-embargod-guess")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token check with an unknown token: status %d", resp.StatusCode)
	}
	if len(*calls) != maxRequests {
		t.Fatalf("upstream calls = %d", len(*calls))
	}
}

func TestProviderRequestQuota(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	for i := 0; i < maxRequests; i++ {
		if resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
	}
	if resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request after quota: status %d", resp.StatusCode)
	}
	if len(*calls) != maxRequests {
		t.Fatalf("upstream calls = %d", len(*calls))
	}
}
