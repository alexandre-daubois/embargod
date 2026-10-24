package modelproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alexandre-daubois/embargod/internal/budget"
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
	token, revoke := mp.Issue(t.Context())
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { revoke() })

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

	body := `{"model":"allowed","input":[{"type":"message","id":"msg_current","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}`
	resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token))

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
	token, revoke := mp.Issue(t.Context())
	t.Cleanup(func() { revoke() })
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
	token, revoke := mp.Issue(t.Context())
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
		"other model":             `{"model":"expensive"}`,
		"remote MCP":              `{"model":"allowed","tools":[{"type":"mcp","server_url":"https://evil.example"}]}`,
		"remote file":             `{"model":"allowed","input":[{"type":"input_file","file_url":"https://evil.example"}]}`,
		"conversation":            `{"model":"allowed","conversation":"conv_other"}`,
		"item reference":          `{"model":"allowed","input":[{"type":"item_reference","id":"item_other"}]}`,
		"implicit item reference": `{"model":"allowed","input":[{"id":"item_other"}]}`,
		"null item reference":     `{"model":"allowed","input":[{"type":null,"id":"item_other"}]}`,
		"multi-agent":             `{"model":"allowed","multi_agent":{"enabled":true,"max_concurrent_subagents":100}}`,
		"nested multi-agent item": `{"model":"allowed","input":[{"type":"multi_agent_call","name":"spawn_agent"}]}`,
		"untyped tool":            `{"model":"allowed","tools":[{"name":"remote"}]}`,
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

func TestAnthropicFallbacksAreRefused(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	body := `{"model":"allowed","max_tokens":16000,"fallbacks":[{"model":"expensive","max_tokens":128000}]}`
	header := withKey("X-Api-Key", token)
	header.Set("Anthropic-Beta", "server-side-fallback-2026-07-01")

	if resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages?beta=true", body, header); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(*calls) != 0 {
		t.Fatalf("the fallback reached the upstream: %+v", *calls)
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

func TestNestedToolsAndUnknownProtocolCapabilitiesFailClosed(t *testing.T) {
	for _, provider := range []Provider{OpenAI, ChatGPT} {
		t.Run(provider.TokenPrefix, func(t *testing.T) {
			for _, body := range []string{
				`{"model":"allowed","input":[{"type":"additional_tools","role":"developer","tools":[{"type":"shell","environment":{"type":"container_auto","network_policy":{"type":"allowlist","allowed_domains":["attacker.invalid"]}}}]}]}`,
				`{"model":"allowed","input":[{"type":"tool_search_output","tools":[{"type":"namespace","name":"n","tools":[{"type":"shell"}]}]}]}`,
				`{"model":"allowed","tools":[{"type":"namespace","name":"n","tools":[{"type":"mcp","server_url":"https://attacker.invalid"}]}]}`,
				`{"model":"allowed","tools":[{"type":"tool_search","execution":"server"}]}`,
				`{"model":"allowed","input":[{"type":"configuration_update","tools":[]}]}`,
				`{"model":"allowed","input":[{"type":"future_provider_tool"}]}`,
				`{"model":"allowed","future_provider_option":true}`,
				`{"model":"allowed","background":true}`,
			} {
				srv, calls, token := setup(t, provider, http.StatusOK)
				route := "/v1/responses"
				if provider.PrivateWorkspace {
					route = "/backend-api/codex/responses"
				}
				if response := callBody(t, srv, http.MethodPost, PathPrefix+route, body, withKey("Authorization", "Bearer "+token)); response.StatusCode != http.StatusForbidden || len(*calls) != 0 {
					t.Fatalf("unsafe request reached upstream: %s (HTTP %d)", body, response.StatusCode)
				}
			}
		})
	}
}

func TestLocalToolConversationPasses(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	body := `{"model":"allowed","tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"read","parameters":{"type":"object","properties":{"type":{"type":"string"}}}}]},{"type":"tool_search","execution":"client"}],"input":[{"role":"user","content":[{"type":"input_text","text":"report"}]},{"type":"reasoning","id":"rs_1","encrypted_content":"opaque","summary":[]},{"type":"function_call","call_id":"c","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"source"},{"type":"additional_tools","role":"developer","tools":[{"type":"custom","name":"local","format":{"type":"text"}}]}],"include":["reasoning.encrypted_content"]}`
	if response := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token)); response.StatusCode != http.StatusOK || len(*calls) != 1 {
		t.Fatalf("local tools rejected: %d", response.StatusCode)
	}
}

func TestTokensShareTheAdvisoryBudgetAndStopOnCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	provider := OpenAI
	provider.Upstream = upstream.URL
	mp, err := New(provider, "key", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mp)
	defer srv.Close()
	ctx, cancel := context.WithCancel(budget.WithLimit(t.Context(), 1, 1<<20))
	defer cancel()
	a, revokeA := mp.Issue(ctx)
	defer revokeA()
	b, revokeB := mp.Issue(ctx)
	defer revokeB()
	if response := call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+a)); response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	if response := call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+b)); response.StatusCode != http.StatusTooManyRequests {
		t.Fatal(response.StatusCode)
	}
	cancel()
	if response := call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+a)); response.StatusCode != http.StatusUnauthorized {
		t.Fatal(response.StatusCode)
	}
}

func TestAnthropicLocalToolsAndContextEdits(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	body := `{"model":"allowed","messages":[{"role":"user","content":[{"type":"text","text":"report"}]},{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{"path":"a.c"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"source"},{"type":"tool_reference","tool_name":"Read"}]}]}],"tools":[{"name":"Read","description":"read","defer_loading":true,"input_schema":{"type":"object"}}],"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}}`
	if response := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages", body, withKey("X-Api-Key", token)); response.StatusCode != http.StatusOK || len(*calls) != 1 {
		t.Fatal("valid local Anthropic conversation rejected")
	}
	body = strings.ReplaceAll(body, "clear_thinking_20251015", "future_remote_compaction")
	if response := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages", body, withKey("X-Api-Key", token)); response.StatusCode != http.StatusForbidden || len(*calls) != 1 {
		t.Fatal("unknown context capability reached Anthropic")
	}
}

func TestCapabilityHeadersAreNotForwarded(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone(); w.WriteHeader(http.StatusOK) }))
	defer up.Close()
	provider := Anthropic
	provider.Upstream = up.URL
	mp, err := New(provider, "key", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	token, revoke := mp.Issue(t.Context())
	defer revoke()
	srv := httptest.NewServer(mp)
	defer srv.Close()
	h := withKey("X-Api-Key", token)
	h.Set("Anthropic-Beta", "context-management-2025-06-27,future-hosted-tools-2026-01-01")
	h.Set("OpenAI-Beta", "agents=enabled")
	h.Set("X-Unknown-Provider-Capability", "enabled")
	if response := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", h); response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	if got.Get("Anthropic-Beta") != "context-management-2025-06-27" || got.Get("OpenAI-Beta") != "" || got.Get("X-Unknown-Provider-Capability") != "" {
		t.Fatal("unreviewed capability header reached upstream")
	}
}

func FuzzProviderRequest(f *testing.F) {
	for _, seed := range []string{`{"model":"allowed"}`, `{"model":"allowed","tools":[{"type":"function","name":"local","parameters":{}}]}`, `{"model":"allowed","input":[{"type":"additional_tools","tools":[{"type":"shell"}]}]}`, `{"model":"allowed","tools":[{"type":{}}]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		for _, provider := range []Provider{Anthropic, OpenAI, ChatGPT} {
			proxy, err := New(provider, "fixture", "allowed")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = proxy.safeBody(strings.NewReader(body))
		}
	})
}
