// Package modelproxy keeps the model API key on the host. A sandboxed agent gets a token that is only
// good for this proxy, which swaps it for the real key on a fixed list of routes and forwards the request.
// Adapted from scrutineer's internal/worker/model_proxy.go.
package modelproxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/php/tamis/internal/budget"
	"github.com/php/tamis/internal/usage"
)

const (
	// PathPrefix is where the proxy serves, the agent's base URL ends with it.
	PathPrefix = "/model-proxy"
	// maxBody caps a forwarded request so a hostile agent cannot make the host buffer unbounded data.
	maxBody     = 1 << 20
	maxRequests = 32
	maxTokens   = 16_000
	tokenPrefix = "tamis-"
	// maxLoggedShape bounds what one refusal adds to the workflow log.
	maxLoggedShape = 8 << 10
)

var errUpstreamRedirect = errors.New("model proxy: upstream redirect refused")

// runKey carries the hash of the token a request came with, so its response is counted for that run.
type runKey struct{}

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
	tokens    map[[sha256.Size]byte]*tokenBudget
	spent     map[[sha256.Size]byte]usage.Usage
	model     string
	accountID string
}

type tokenBudget struct {
	remaining int
	ctx       context.Context
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

	p := &Proxy{provider: provider, key: key, model: model, tokens: map[[sha256.Size]byte]*tokenBudget{}, spent: map[[sha256.Size]byte]usage.Usage{}}
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
			// New provider capabilities must not be enabled through a client-supplied header.
			pr.Out.Header = http.Header{}
			pr.Out.Header.Set("Content-Type", "application/json")
			pr.Out.Header.Set("Accept", pr.In.Header.Get("Accept"))
			if provider.UntypedTools {
				pr.Out.Header.Set("Anthropic-Version", "2023-06-01")
				var betas []string
				for _, beta := range strings.Split(pr.In.Header.Get("Anthropic-Beta"), ",") {
					beta = strings.TrimSpace(beta)
					if slices.Contains([]string{"claude-code-20250219", "interleaved-thinking-2025-05-14", "fine-grained-tool-streaming-2025-05-14", "context-management-2025-06-27", "effort-2025-11-24", "adaptive-thinking-2026-01-28", "structured-outputs-2025-11-13", "prompt-caching-2024-07-31", "tool-search-tool-2025-10-19", "per-turn-control-2026-07-01", "mid-conversation-tool-changes-2026-07-01", "thinking-display-updates-2026-08-18", "thinking-token-count-2026-05-13", "prompt-caching-scope-2026-01-05"}, beta) {
						betas = append(betas, beta)
					}
				}
				if len(betas) > 0 {
					pr.Out.Header.Set("Anthropic-Beta", strings.Join(betas, ","))
				}
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
			if resp.StatusCode >= http.StatusBadRequest {
				slog.Warn("model provider refused a request", "method", resp.Request.Method, "route", resp.Request.URL.Path, "status", resp.StatusCode)
			}
			if provider.PrivateWorkspace && resp.StatusCode < http.StatusMultipleChoices {
				switch {
				case strings.HasSuffix(resp.Request.URL.Path, "/v1/user-auth-credential/whoami"):
					return p.redactIdentity(resp)
				case strings.HasSuffix(resp.Request.URL.Path, "/wham/config/bundle"):
					return replaceBody(resp, []byte(`{"config_toml":{"enterprise_managed":[]},"requirements_toml":{"enterprise_managed":[]}}`))
				}
			}
			if resp.Request.Method == http.MethodPost && resp.StatusCode < http.StatusMultipleChoices && !strings.HasSuffix(resp.Request.URL.Path, "/count_tokens") {
				sum, _ := resp.Request.Context().Value(runKey{}).([sha256.Size]byte)
				resp.Body = &usageReader{
					ReadCloser: resp.Body,
					stream:     strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"),
					done:       func(u usage.Usage) { p.record(sum, u) },
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

// Issue mints a token for one agent run, revoke invalidates it and returns what the run spent. Only its hash is kept.
func (p *Proxy) Issue(ctx context.Context) (token string, revoke func() usage.Usage) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token = cmp.Or(p.provider.TokenPrefix, tokenPrefix) + hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	p.mu.Lock()
	p.tokens[sum] = &tokenBudget{remaining: maxRequests, ctx: ctx}
	p.mu.Unlock()

	return token, func() usage.Usage {
		p.mu.Lock()
		defer p.mu.Unlock()
		spent := p.spent[sum]
		delete(p.tokens, sum)
		delete(p.spent, sum)

		return spent
	}
}

func (p *Proxy) record(sum [sha256.Size]byte, u usage.Usage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, issued := p.tokens[sum]; issued {
		p.spent[sum] = p.spent[sum].Plus(u)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sum, token := p.authorized(r)
	if token == nil {
		http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), runKey{}, sum))
	if r.URL.RawPath != "" || (r.URL.RawQuery != "" && (!p.provider.BetaQuery || r.URL.RawQuery != "beta=true")) || path.Clean(route) != route || !p.provider.Routes(r.Method, route) {
		slog.Info("model proxy refused a route", "method", r.Method, "route", truncate(route, maxLoggedShape))
		http.Error(w, "route not permitted", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "invalid provider request", http.StatusForbidden)
			return
		}
		body, err := p.safeBody(bytes.NewReader(raw))
		if err != nil {
			if errors.Is(err, errRequestTooLarge) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			var v any
			_ = json.Unmarshal(raw, &v)
			slog.Warn("model proxy refused a request", "route", route, "shape", truncate(shape(v), maxLoggedShape))
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		if !budget.Take(token.ctx, len(body)) {
			http.Error(w, "provider budget exhausted", http.StatusTooManyRequests)
			return
		}
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Anthropic-Beta")), "mcp") {
		http.Error(w, "provider capability not permitted", http.StatusForbidden)
		return
	}
	r.URL.Path = route
	p.proxy.ServeHTTP(w, r)
}

func (p *Proxy) authorized(r *http.Request) ([sha256.Size]byte, *tokenBudget) {
	token := r.Header.Get("X-Api-Key")
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); token == "" && ok {
		token = bearer
	}
	if token == "" {
		return [sha256.Size]byte{}, nil
	}
	sum := sha256.Sum256([]byte(token))
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.tokens[sum]
	if b == nil || b.remaining <= 0 || b.ctx.Err() != nil {
		return sum, nil
	}
	b.remaining--

	return sum, b
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
		"chatgpt_user_id":            "tamis",
		"chatgpt_account_id":         "tamis",
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
	if !ok || model != p.model || !safeRequest(v, p.provider.UntypedTools) {
		return nil, errors.New("provider request not permitted")
	}
	delete(v, "client_metadata")
	for _, key := range []string{"previous_response_id", "conversation", "prompt", "fallbacks", "multi_agent"} {
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

// shape describes a refused request by its keys and protocol type names, so a log shows which position the
// filter refused without the conversation text it carries.
func shape(v any) string {
	switch v := v.(type) {
	case map[string]any:
		keys := slices.Sorted(maps.Keys(v))
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if s, ok := v[k].(string); ok && (k == "type" || k == "role" || k == "execution") {
				parts = append(parts, k+"="+s)
				continue
			}
			parts = append(parts, k+":"+shape(v[k]))
		}
		return "{" + strings.Join(parts, " ") + "}"
	case []any:
		var parts []string
		for _, item := range v {
			if s := shape(item); !slices.Contains(parts, s) {
				parts = append(parts, s)
			}
		}
		return "[" + strings.Join(parts, " ") + "]"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "..."
}
