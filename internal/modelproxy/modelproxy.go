// Package modelproxy keeps the model API key on the host. A sandboxed agent gets a token that is only
// good for this proxy, which swaps it for the real key on a fixed list of routes and forwards the request.
// Adapted from scrutineer's internal/worker/model_proxy.go.
package modelproxy

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
)

const (
	// PathPrefix is where the proxy serves, the agent's base URL ends with it.
	PathPrefix = "/model-proxy"
	// maxBody caps a forwarded request so a hostile agent cannot make the host buffer unbounded data.
	maxBody     = 8 << 20
	maxRequests = 32
	maxTokens   = 16_000
	tokenPrefix = "embargod-"
)

var errUpstreamRedirect = errors.New("model proxy: upstream redirect refused")

// Provider describes one model API: where it lives, which routes an agent may call and how the key is sent.
type Provider struct {
	Upstream string
	// Upstreams sends the routes under each prefix to their own upstream, the prefix itself is dropped.
	Upstreams map[string]string
	// TokenPrefix starts the tokens the agent gets, when its CLI recognises a credential by its prefix.
	TokenPrefix string
	Routes      func(method, route string) bool
	SetKey      func(h http.Header, key string)
	NoStore     bool
	// StoreOff forces store to false only, for an upstream that rejects the other NoStore defaults.
	StoreOff     bool
	UntypedTools bool
	BetaQuery    bool
	// PrivateWorkspace redacts ChatGPT identity and managed configuration before they reach Codex.
	PrivateWorkspace bool
}

var Anthropic = Provider{
	Upstream: "https://api.anthropic.com",
	Routes: func(method, route string) bool {
		switch {
		case method == http.MethodPost:
			return route == "/v1/messages" || route == "/v1/messages/count_tokens"
		default:
			return false
		}
	},
	SetKey:       func(h http.Header, key string) { h.Set("X-Api-Key", key) },
	UntypedTools: true,
	BetaQuery:    true,
}

var OpenAI = Provider{
	Upstream: "https://api.openai.com",
	Routes: func(method, route string) bool {
		switch {
		case method == http.MethodPost:
			return route == "/v1/responses"
		default:
			return false
		}
	},
	SetKey:  func(h http.Header, key string) { h.Set("Authorization", "Bearer "+key) },
	NoStore: true,
}

// ChatGPT serves Codex signed in with a Codex access token: it checks the token on auth.openai.com, then
// calls the model through the ChatGPT backend instead of the OpenAI API.
var ChatGPT = Provider{
	Upstreams: map[string]string{
		"/auth":        "https://auth.openai.com/api/accounts",
		"/backend-api": "https://chatgpt.com/backend-api",
	},
	Routes: func(method, route string) bool {
		switch method {
		case http.MethodGet:
			// Codex refuses to start without the workspace's managed configuration.
			return route == "/auth/v1/user-auth-credential/whoami" || route == "/backend-api/wham/config/bundle"
		case http.MethodPost:
			return route == "/backend-api/codex/responses"
		default:
			return false
		}
	},
	TokenPrefix:      "at-" + tokenPrefix,
	SetKey:           func(h http.Header, key string) { h.Set("Authorization", "Bearer "+key) },
	StoreOff:         true,
	PrivateWorkspace: true,
}

type Proxy struct {
	provider Provider
	key      string
	proxy    *httputil.ReverseProxy

	mu        sync.RWMutex
	tokens    map[[sha256.Size]byte]int
	model     string
	accountID string
}

func New(provider Provider, key, model string) (*Proxy, error) {
	if key == "" {
		return nil, errors.New("model proxy: an API key is required")
	}
	if model == "" {
		return nil, errors.New("model proxy: a model is required")
	}
	upstreams := map[string]*url.URL{}
	for prefix, raw := range provider.Upstreams {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("model proxy: %w", err)
		}
		upstreams[prefix] = u
	}
	if provider.Upstreams == nil {
		u, err := url.Parse(provider.Upstream)
		if err != nil {
			return nil, fmt.Errorf("model proxy: %w", err)
		}
		upstreams[""] = u
	}

	p := &Proxy{provider: provider, key: key, model: model, tokens: map[[sha256.Size]byte]int{}}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// ServeHTTP only forwards permitted routes, each under exactly one prefix.
			var upstream *url.URL
			route := pr.In.URL.Path
			for prefix, u := range upstreams {
				if rest, ok := strings.CutPrefix(pr.In.URL.Path, prefix); ok && (prefix == "" || strings.HasPrefix(rest, "/")) {
					upstream, route = u, rest
				}
			}
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = upstream.Scheme, upstream.Host, upstream.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = upstream.Path+route, ""
			for _, h := range []string{"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie", "OpenAI-Organization", "OpenAI-Project", "ChatGPT-Account-Id", "Accept-Encoding"} {
				pr.Out.Header.Del(h)
			}
			provider.SetKey(pr.Out.Header, key)
			if provider.PrivateWorkspace && strings.HasPrefix(pr.In.URL.Path, "/backend-api/") {
				p.mu.RLock()
				accountID := p.accountID
				p.mu.RUnlock()
				if accountID != "" {
					pr.Out.Header.Set("ChatGPT-Account-Id", accountID)
				}
			}
		},
		// Stream server-sent events to the agent as they arrive.
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
				return errUpstreamRedirect
			}
			if provider.PrivateWorkspace && resp.StatusCode < http.StatusMultipleChoices {
				switch {
				case strings.HasSuffix(resp.Request.URL.Path, "/v1/user-auth-credential/whoami"):
					return p.redactIdentity(resp)
				case strings.HasSuffix(resp.Request.URL.Path, "/wham/config/bundle"):
					return replaceBody(resp, []byte(`{"config_toml":{"enterprise_managed":[]},"requirements_toml":{"enterprise_managed":[]}}`))
				}
			}

			return nil
		},
		// Upstream errors are not logged: they could carry parts of the conversation.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "model proxy could not reach the upstream API", http.StatusBadGateway)
		},
	}

	return p, nil
}

// Issue mints a token for one agent run, revoke invalidates it. Only its hash is kept.
func (p *Proxy) Issue() (token string, revoke func()) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token = cmp.Or(p.provider.TokenPrefix, tokenPrefix) + hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	p.mu.Lock()
	p.tokens[sum] = maxRequests
	p.mu.Unlock()

	return token, func() {
		p.mu.Lock()
		delete(p.tokens, sum)
		p.mu.Unlock()
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !p.authorized(r) {
		http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	if r.URL.RawPath != "" || (r.URL.RawQuery != "" && (!p.provider.BetaQuery || r.URL.RawQuery != "beta=true")) || path.Clean(route) != route || !p.provider.Routes(r.Method, route) {
		http.Error(w, "route not permitted", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost {
		body, err := p.safeBody(r.Body)
		if err != nil {
			if errors.Is(err, errRequestTooLarge) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Anthropic-Beta")), "mcp") {
		http.Error(w, "provider capability not permitted", http.StatusForbidden)
		return
	}
	r.URL.Path = route
	p.proxy.ServeHTTP(w, r)
}

func (p *Proxy) authorized(r *http.Request) bool {
	token := r.Header.Get("X-Api-Key")
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); token == "" && ok {
		token = bearer
	}
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tokens[sum] <= 0 {
		return false
	}
	p.tokens[sum]--

	return true
}

func (p *Proxy) redactIdentity(resp *http.Response) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return errors.New("model proxy: invalid identity response")
	}
	var identity struct {
		AccountID string `json:"chatgpt_account_id"`
		PlanType  string `json:"chatgpt_plan_type"`
		FedRAMP   bool   `json:"chatgpt_account_is_fedramp"`
	}
	if err := json.Unmarshal(body, &identity); err != nil || identity.AccountID == "" || identity.PlanType == "" {
		return errors.New("model proxy: invalid identity response")
	}
	p.mu.Lock()
	p.accountID = identity.AccountID
	p.mu.Unlock()
	redacted, _ := json.Marshal(map[string]any{
		"email":                      nil,
		"chatgpt_user_id":            "embargod",
		"chatgpt_account_id":         "embargod",
		"chatgpt_plan_type":          identity.PlanType,
		"chatgpt_account_is_fedramp": identity.FedRAMP,
	})

	return replaceBody(resp, redacted)
}

func replaceBody(resp *http.Response, body []byte) error {
	if resp.Body != nil {
		resp.Body.Close()
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")

	return nil
}

var errRequestTooLarge = errors.New("request too large")

func (p *Proxy) safeBody(body io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxBody+1))
	if err != nil {
		return nil, errors.New("invalid provider request")
	}
	if len(b) > maxBody {
		return nil, errRequestTooLarge
	}
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("invalid provider request")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("invalid provider request")
	}
	model, ok := v["model"].(string)
	if !ok || model != p.model || unsafeProviderValue(v) || unsafeToolsField(v["tools"], p.provider.UntypedTools) {
		return nil, errors.New("provider request not permitted")
	}
	for _, key := range []string{"previous_response_id", "conversation", "prompt"} {
		if _, ok := v[key]; ok {
			return nil, errors.New("provider request not permitted")
		}
	}
	for _, key := range []string{"max_tokens", "max_output_tokens"} {
		if raw, ok := v[key]; ok {
			n, ok := raw.(json.Number)
			if !ok {
				return nil, errors.New("provider request not permitted")
			}
			value, err := n.Int64()
			if err != nil || value < 1 {
				return nil, errors.New("provider request not permitted")
			}
			if value > maxTokens {
				v[key] = maxTokens
			}
		}
	}
	if p.provider.StoreOff {
		v["store"] = false
	}
	if p.provider.NoStore {
		v["store"] = false
		v["background"] = false
		if _, ok := v["max_output_tokens"]; !ok {
			v["max_output_tokens"] = maxTokens
		}
	}

	return json.Marshal(v)
}

func unsafeProviderValue(v any) bool {
	switch value := v.(type) {
	case []any:
		for _, item := range value {
			if unsafeProviderValue(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range value {
			switch key {
			case "mcp_servers", "server_url", "image_url", "file_url", "file_id", "vector_store_ids":
				return true
			case "type":
				if kind, ok := item.(string); ok {
					for _, forbidden := range []string{"mcp", "web", "computer", "code_interpreter", "file_search", "image_generation"} {
						if strings.Contains(strings.ToLower(kind), forbidden) {
							return true
						}
					}
				}
			}
			if kind, _ := value["type"].(string); key == "url" && kind == "url" {
				return true
			}
			if unsafeProviderValue(item) {
				return true
			}
		}
	}

	return false
}

func unsafeTools(v any, untyped bool) bool {
	tools, ok := v.([]any)
	if !ok {
		return true
	}
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		if !ok {
			return true
		}
		kind, ok := tool["type"].(string)
		if (!ok && !untyped) || (ok && !slices.Contains([]string{"function", "custom", "tool_search", "local_shell", "apply_patch"}, kind)) {
			return true
		}
	}

	return false
}

func unsafeToolsField(v any, untyped bool) bool {
	return v != nil && unsafeTools(v, untyped)
}
