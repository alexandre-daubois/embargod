package modelproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/tamis/internal/budget"
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	req.Header = header
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
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

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Set-Cookie"))
	require.Len(t, *calls, 1)
	got := (*calls)[0]
	require.Equal(t, "/v1/messages", got.path)
	require.Equal(t, "real-key", got.apiKey)
	require.Empty(t, got.auth)
	require.Empty(t, got.cookie)
}

func TestOpenAISwapsTheBearerToken(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)

	body := `{"model":"allowed","input":[{"type":"message","id":"msg_current","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}`
	resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token))

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, *calls, 1)
	require.Equal(t, "Bearer real-key", (*calls)[0].auth)
	require.Empty(t, (*calls)[0].apiKey)
	require.Contains(t, (*calls)[0].body, `"store":false`, "unsafe OpenAI defaults were not overridden")
	require.Contains(t, (*calls)[0].body, `"background":false`, "unsafe OpenAI defaults were not overridden")
}

func TestChatGPTSwapsTheAccessTokenOnBothUpstreams(t *testing.T) {
	srv, calls, token := setup(t, ChatGPT, http.StatusOK)
	require.True(t, strings.HasPrefix(token, "at-tamis-"), "Codex only reads a token starting with at- as an access token: %q", token)

	whoami := call(t, srv, http.MethodGet, PathPrefix+"/auth/v1/user-auth-credential/whoami", withKey("Authorization", "Bearer "+token))
	identity, _ := io.ReadAll(whoami.Body)
	backendKey := withKey("Authorization", "Bearer "+token)
	backendKey.Set("ChatGPT-Account-Id", "attacker-controlled")
	bundle := call(t, srv, http.MethodGet, PathPrefix+"/backend-api/wham/config/bundle", backendKey)
	managed, _ := io.ReadAll(bundle.Body)
	responses := call(t, srv, http.MethodPost, PathPrefix+"/backend-api/codex/responses", backendKey)

	require.Equal(t, http.StatusOK, whoami.StatusCode)
	require.Equal(t, http.StatusOK, bundle.StatusCode)
	require.Equal(t, http.StatusOK, responses.StatusCode)
	require.Len(t, *calls, 3)
	for i, want := range []string{"/api/accounts/v1/user-auth-credential/whoami", "/backend-api/wham/config/bundle", "/backend-api/codex/responses"} {
		got := (*calls)[i]
		assert.Equal(t, want, got.path)
		assert.Equal(t, "Bearer real-key", got.auth, want)
		assert.Empty(t, got.cookie, want)
	}
	assert.Empty(t, (*calls)[0].accountID, "workspace identity was not applied server-side only")
	assert.Equal(t, "account-secret", (*calls)[1].accountID, "workspace identity was not applied server-side only")
	assert.Equal(t, "account-secret", (*calls)[2].accountID, "workspace identity was not applied server-side only")
	assert.NotContains(t, string(identity), "secret", "private workspace response reached the agent")
	assert.NotContains(t, string(identity), "security@example.com", "private workspace response reached the agent")
	assert.Contains(t, string(identity), `"chatgpt_account_id":"tamis"`, "private workspace response reached the agent")
	assert.NotContains(t, string(managed), "internal", "private workspace response reached the agent")
	assert.Contains(t, string(managed), `"enterprise_managed":[]`, "private workspace response reached the agent")
	body := (*calls)[2].body
	assert.Contains(t, body, `"store":false`, "the ChatGPT backend only accepts store set to false")
	assert.NotContains(t, body, "background", "the ChatGPT backend only accepts store set to false")
	assert.NotContains(t, body, "max_output_tokens", "the ChatGPT backend only accepts store set to false")
}

func TestChatGPTRefusesAnIdentityWithoutAccount(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"email":"security@example.com","chatgpt_plan_type":"enterprise"}`)
	}))
	t.Cleanup(up.Close)
	p := ChatGPT
	p.Upstreams = map[string]string{"/auth": up.URL + "/api/accounts", "/backend-api": up.URL + "/backend-api"}
	mp, err := New(p, "real-key", "allowed")
	require.NoError(t, err)
	token, revoke := mp.Issue(t.Context())
	t.Cleanup(func() { revoke() })
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)

	resp := call(t, srv, http.MethodGet, PathPrefix+"/auth/v1/user-auth-credential/whoami", withKey("Authorization", "Bearer "+token))
	body, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.NotContains(t, string(body), "security@example.com")
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
		assert.Equal(t, http.StatusForbidden, call(t, srv, tc.method, PathPrefix+tc.path, withKey("Authorization", "Bearer "+token)).StatusCode, "%s %s", tc.method, tc.path)
	}
	require.Empty(t, *calls, "refused routes reached the upstream")
}

func TestRefusals(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)

	for name, tc := range map[string]struct {
		method, path string
		header       http.Header
		status       int
	}{
		"no token":       {http.MethodPost, PathPrefix + "/v1/messages", http.Header{}, http.StatusUnauthorized},
		"unknown token":  {http.MethodPost, PathPrefix + "/v1/messages", withKey("X-Api-Key", "tamis-guess"), http.StatusUnauthorized},
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
			require.Equal(t, tc.status, call(t, srv, tc.method, tc.path, tc.header).StatusCode)
		})
	}
	require.Empty(t, *calls, "nothing should reach the upstream")
}

func TestRevokedTokenIsRefused(t *testing.T) {
	mp, err := New(Anthropic, "real-key", "allowed")
	require.NoError(t, err)
	token, revoke := mp.Issue(t.Context())
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)

	revoke()

	require.Equal(t, http.StatusUnauthorized, call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)).StatusCode)
}

func TestUpstreamRedirectIsNotRelayed(t *testing.T) {
	srv, _, token := setup(t, Anthropic, http.StatusFound)

	resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token))

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"))
}

func TestNewRequiresAKey(t *testing.T) {
	_, err := New(Anthropic, "", "allowed")
	require.Error(t, err)
}

func TestNewRequiresAModel(t *testing.T) {
	_, err := New(Anthropic, "real-key", "")
	require.Error(t, err)
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
			require.Equal(t, http.StatusForbidden, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token)).StatusCode)
		})
	}
	require.Empty(t, *calls, "nothing should reach the upstream")
}

func TestAnthropicFallbacksAreRefused(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	body := `{"model":"allowed","max_tokens":16000,"fallbacks":[{"model":"expensive","max_tokens":128000}]}`
	header := withKey("X-Api-Key", token)
	header.Set("Anthropic-Beta", "server-side-fallback-2026-07-01")

	require.Equal(t, http.StatusForbidden, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages?beta=true", body, header).StatusCode)
	require.Empty(t, *calls, "the fallback reached the upstream")
}

func TestProviderTokenLimitIsClamped(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	resp := callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", `{"model":"allowed","max_output_tokens":16001}`, withKey("Authorization", "Bearer "+token))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, *calls, 1)
	require.Contains(t, (*calls)[0].body, `"max_output_tokens":16000`)
}

func TestEveryAccessTokenRequestSpendsTheQuota(t *testing.T) {
	srv, calls, token := setup(t, ChatGPT, http.StatusOK)
	whoami := PathPrefix + "/auth/v1/user-auth-credential/whoami"
	for range maxRequests {
		call(t, srv, http.MethodGet, whoami, withKey("Authorization", "Bearer "+token))
	}
	require.Equal(t, http.StatusUnauthorized, call(t, srv, http.MethodPost, PathPrefix+"/backend-api/codex/responses", withKey("Authorization", "Bearer "+token)).StatusCode, "request after token checks")
	require.Equal(t, http.StatusUnauthorized, call(t, srv, http.MethodGet, whoami, withKey("Authorization", "Bearer at-tamis-guess")).StatusCode, "token check with an unknown token")
	require.Len(t, *calls, maxRequests)
}

func TestProviderRequestQuota(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	for i := 0; i < maxRequests; i++ {
		require.Equal(t, http.StatusOK, call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)).StatusCode, "request %d", i+1)
	}
	require.Equal(t, http.StatusUnauthorized, call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", token)).StatusCode, "request after quota")
	require.Len(t, *calls, maxRequests)
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
				require.Equal(t, http.StatusForbidden, callBody(t, srv, http.MethodPost, PathPrefix+route, body, withKey("Authorization", "Bearer "+token)).StatusCode, "unsafe request reached upstream: %s", body)
				require.Empty(t, *calls, "unsafe request reached upstream: %s", body)
			}
		})
	}
}

func TestLocalToolConversationPasses(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	body := `{"model":"allowed","tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"read","parameters":{"type":"object","properties":{"type":{"type":"string"}}}}]},{"type":"tool_search","execution":"client"}],"input":[{"role":"user","content":[{"type":"input_text","text":"report"}]},{"type":"reasoning","id":"rs_1","encrypted_content":"opaque","summary":[]},{"type":"function_call","call_id":"c","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"source"},{"type":"additional_tools","role":"developer","tools":[{"type":"custom","name":"local","format":{"type":"text"}}]}],"include":["reasoning.encrypted_content"]}`
	require.Equal(t, http.StatusOK, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token)).StatusCode, "local tools rejected")
	require.Len(t, *calls, 1, "local tools rejected")
}

func TestTokensShareTheAdvisoryBudgetAndStopOnCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	provider := OpenAI
	provider.Upstream = upstream.URL
	mp, err := New(provider, "key", "allowed")
	require.NoError(t, err)
	srv := httptest.NewServer(mp)
	defer srv.Close()
	ctx, cancel := context.WithCancel(budget.WithLimit(t.Context(), 1, 1<<20))
	defer cancel()
	a, revokeA := mp.Issue(ctx)
	defer revokeA()
	b, revokeB := mp.Issue(ctx)
	defer revokeB()
	require.Equal(t, http.StatusOK, call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+a)).StatusCode)
	require.Equal(t, http.StatusTooManyRequests, call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+b)).StatusCode)
	cancel()
	require.Equal(t, http.StatusUnauthorized, call(t, srv, http.MethodPost, PathPrefix+"/v1/responses", withKey("Authorization", "Bearer "+a)).StatusCode)
}

func TestAnthropicLocalToolsAndContextEdits(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	body := `{"model":"allowed","messages":[{"role":"user","content":[{"type":"text","text":"report"}]},{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{"path":"a.c"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"source"},{"type":"tool_reference","tool_name":"Read"}]}]}],"tools":[{"name":"Read","description":"read","defer_loading":true,"input_schema":{"type":"object"}}],"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}}`
	require.Equal(t, http.StatusOK, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages", body, withKey("X-Api-Key", token)).StatusCode, "valid local Anthropic conversation rejected")
	require.Len(t, *calls, 1, "valid local Anthropic conversation rejected")
	body = strings.ReplaceAll(body, "clear_thinking_20251015", "future_remote_compaction")
	require.Equal(t, http.StatusForbidden, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/messages", body, withKey("X-Api-Key", token)).StatusCode, "unknown context capability reached Anthropic")
	require.Len(t, *calls, 1, "unknown context capability reached Anthropic")
}

func TestCapabilityHeadersAreNotForwarded(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone(); w.WriteHeader(http.StatusOK) }))
	defer up.Close()
	provider := Anthropic
	provider.Upstream = up.URL
	mp, err := New(provider, "key", "allowed")
	require.NoError(t, err)
	token, revoke := mp.Issue(t.Context())
	defer revoke()
	srv := httptest.NewServer(mp)
	defer srv.Close()
	h := withKey("X-Api-Key", token)
	h.Set("Anthropic-Beta", "context-management-2025-06-27,future-hosted-tools-2026-01-01")
	h.Set("OpenAI-Beta", "agents=enabled")
	h.Set("X-Unknown-Provider-Capability", "enabled")
	require.Equal(t, http.StatusOK, call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", h).StatusCode)
	require.Equal(t, "context-management-2025-06-27", got.Get("Anthropic-Beta"), "unreviewed capability header reached upstream")
	require.Empty(t, got.Get("OpenAI-Beta"), "unreviewed capability header reached upstream")
	require.Empty(t, got.Get("X-Unknown-Provider-Capability"), "unreviewed capability header reached upstream")
}

// Each reviewed protocol position passes, and one unreviewed field or shape at that position is refused.
func TestRequestShapes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider Provider
		accepted map[string]string
		refused  map[string]string
	}{
		{
			name:     "anthropic",
			provider: Anthropic,
			accepted: map[string]string{
				"thinking":        `{"model":"allowed","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"s"},{"type":"redacted_thinking","data":"d"}]}]}`,
				"effort":          `{"model":"allowed","messages":[{"role":"user","content":"x","output_config":{"effort":"high"}}]}`,
				"clear tool uses": `{"model":"allowed","context_management":{"edits":[{"type":"clear_tool_uses_20250919","keep":{"type":"tool_uses","value":3}}]}}`,
				"system blocks":   `{"model":"allowed","system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}]}`,
			},
			refused: map[string]string{
				"tools object":             `{"model":"allowed","tools":{}}`,
				"tool string":              `{"model":"allowed","tools":["Read"]}`,
				"hosted tool":              `{"model":"allowed","tools":[{"type":"web_search_20250305","name":"web_search"}]}`,
				"tool field":               `{"model":"allowed","tools":[{"name":"Read","input_schema":{},"mcp_server":"s"}]}`,
				"messages object":          `{"model":"allowed","messages":{}}`,
				"message field":            `{"model":"allowed","messages":[{"role":"user","content":"x","container":"c"}]}`,
				"output config string":     `{"model":"allowed","messages":[{"role":"user","content":"x","output_config":"high"}]}`,
				"output config field":      `{"model":"allowed","messages":[{"role":"user","content":"x","output_config":{"effort":"high","task_budget":1}}]}`,
				"system object":            `{"model":"allowed","system":{}}`,
				"system string block":      `{"model":"allowed","system":["s"]}`,
				"text field":               `{"model":"allowed","system":[{"type":"text","text":"s","citations":[]}]}`,
				"thinking field":           `{"model":"allowed","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"s","source":"x"}]}]}`,
				"tool use field":           `{"model":"allowed","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{},"caller":{}}]}]}`,
				"tool result field":        `{"model":"allowed","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","container":"c"}]}]}`,
				"tool reference field":     `{"model":"allowed","messages":[{"role":"user","content":[{"type":"tool_reference","tool_name":"Read","server":"s"}]}]}`,
				"server tool block":        `{"model":"allowed","messages":[{"role":"assistant","content":[{"type":"server_tool_use","id":"s","name":"web_search","input":{}}]}]}`,
				"context management list":  `{"model":"allowed","context_management":[]}`,
				"context management field": `{"model":"allowed","context_management":{"edits":[],"compaction":true}}`,
				"edits object":             `{"model":"allowed","context_management":{"edits":{}}}`,
				"edit string":              `{"model":"allowed","context_management":{"edits":["clear_thinking_20251015"]}}`,
				"clear thinking field":     `{"model":"allowed","context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all","trigger":{}}]}}`,
				"clear tool uses field":    `{"model":"allowed","context_management":{"edits":[{"type":"clear_tool_uses_20250919","server":"s"}]}}`,
				"token limit string":       `{"model":"allowed","max_tokens":"16000"}`,
				"token limit zero":         `{"model":"allowed","max_tokens":0}`,
			},
		},
		{
			name:     "openai",
			provider: OpenAI,
			accepted: map[string]string{
				"string input":      `{"model":"allowed","input":"report"}`,
				"local tools":       `{"model":"allowed","tools":[{"type":"local_shell"},{"type":"apply_patch"},{"type":"custom","name":"c","format":{"type":"text"}}]}`,
				"named tool choice": `{"model":"allowed","tool_choice":{"type":"function","name":"read"}}`,
				"client search":     `{"model":"allowed","input":[{"type":"tool_search_call","call_id":"c","arguments":{},"execution":"client"},{"type":"custom_tool_call_output","call_id":"c","output":[{"type":"input_text","text":"x"}]}]}`,
			},
			refused: map[string]string{
				"include string":          `{"model":"allowed","include":"reasoning.encrypted_content"}`,
				"include other":           `{"model":"allowed","include":["file_search_call.results"]}`,
				"function field":          `{"model":"allowed","tools":[{"type":"function","name":"f","server_url":"https://attacker.invalid"}]}`,
				"custom field":            `{"model":"allowed","tools":[{"type":"custom","name":"c","server_url":"https://attacker.invalid"}]}`,
				"local shell field":       `{"model":"allowed","tools":[{"type":"local_shell","environment":{}}]}`,
				"client search field":     `{"model":"allowed","tools":[{"type":"tool_search","execution":"client","server_url":"https://attacker.invalid"}]}`,
				"tool choice string":      `{"model":"allowed","tool_choice":"web_search"}`,
				"tool choice hosted":      `{"model":"allowed","tool_choice":{"type":"mcp","server_label":"s"}}`,
				"tool choice field":       `{"model":"allowed","tool_choice":{"type":"function","name":"f","server":"s"}}`,
				"input number":            `{"model":"allowed","input":1}`,
				"input string item":       `{"model":"allowed","input":["report"]}`,
				"message field":           `{"model":"allowed","input":[{"role":"user","content":"x","file_url":"https://attacker.invalid"}]}`,
				"message image":           `{"model":"allowed","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://attacker.invalid"}]}]}`,
				"reasoning field":         `{"model":"allowed","input":[{"type":"reasoning","summary":[],"server":"s"}]}`,
				"function call field":     `{"model":"allowed","input":[{"type":"function_call","call_id":"c","name":"f","arguments":"{}","server":"s"}]}`,
				"call output field":       `{"model":"allowed","input":[{"type":"function_call_output","call_id":"c","output":"x","server":"s"}]}`,
				"additional tools field":  `{"model":"allowed","input":[{"type":"additional_tools","tools":[],"server":"s"}]}`,
				"server tool search call": `{"model":"allowed","input":[{"type":"tool_search_call","call_id":"c","arguments":{},"execution":"server"}]}`,
				"tool search call field":  `{"model":"allowed","input":[{"type":"tool_search_call","call_id":"c","execution":"client","server":"s"}]}`,
			},
		},
	} {
		proxy, err := New(tc.provider, "key", "allowed")
		require.NoError(t, err)
		for name, body := range tc.accepted {
			t.Run(tc.name+"/accepted/"+name, func(t *testing.T) {
				_, err := proxy.safeBody(strings.NewReader(body))
				require.NoError(t, err)
			})
		}
		for name, body := range tc.refused {
			t.Run(tc.name+"/refused/"+name, func(t *testing.T) {
				_, err := proxy.safeBody(strings.NewReader(body))
				require.EqualError(t, err, "provider request not permitted")
			})
		}
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	proxy, err := New(OpenAI, "key", "allowed")
	require.NoError(t, err)
	for name, body := range map[string]string{
		"not JSON":      `model=allowed`,
		"trailing data": `{"model":"allowed"} {"model":"allowed","tools":[{"type":"mcp"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := proxy.safeBody(strings.NewReader(body))
			require.EqualError(t, err, "invalid provider request")
		})
	}
	_, err = proxy.safeBody(strings.NewReader(`{"model":"allowed","input":"` + strings.Repeat("x", maxBody) + `"}`))
	require.ErrorIs(t, err, errRequestTooLarge)
}

func TestOversizedRequestIsRefusedBeforeTheUpstream(t *testing.T) {
	srv, calls, token := setup(t, OpenAI, http.StatusOK)
	body := `{"model":"allowed","input":"` + strings.Repeat("x", maxBody) + `"}`
	require.Equal(t, http.StatusRequestEntityTooLarge, callBody(t, srv, http.MethodPost, PathPrefix+"/v1/responses", body, withKey("Authorization", "Bearer "+token)).StatusCode)
	require.Empty(t, *calls)
}

func TestMCPBetaHeaderIsRefused(t *testing.T) {
	srv, calls, token := setup(t, Anthropic, http.StatusOK)
	header := withKey("X-Api-Key", token)
	header.Set("Anthropic-Beta", "mcp-client-2025-04-04")
	require.Equal(t, http.StatusForbidden, call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", header).StatusCode)
	require.Empty(t, *calls)
}

func FuzzProviderRequest(f *testing.F) {
	for _, seed := range []string{`{"model":"allowed"}`, `{"model":"allowed","tools":[{"type":"function","name":"local","parameters":{}}]}`, `{"model":"allowed","input":[{"type":"additional_tools","tools":[{"type":"shell"}]}]}`, `{"model":"allowed","tools":[{"type":{}}]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		for _, provider := range []Provider{Anthropic, OpenAI, ChatGPT} {
			proxy, err := New(provider, "fixture", "allowed")
			require.NoError(t, err)
			_, _ = proxy.safeBody(strings.NewReader(body))
		}
	})
}
