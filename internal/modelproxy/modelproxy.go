// Package modelproxy keeps the model API key on the host. A sandboxed agent gets a token that is only
// good for this proxy, which swaps it for the real key on a fixed list of routes and forwards the request.
// Adapted from scrutineer's internal/worker/model_proxy.go.
package modelproxy

import (
	"bytes"
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
	Upstream     string
	Routes       func(method, route string) bool
	SetKey       func(h http.Header, key string)
	NoStore      bool
	UntypedTools bool
	BetaQuery    bool
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

type Proxy struct {
	provider Provider
	key      string
	proxy    *httputil.ReverseProxy

	mu     sync.RWMutex
	tokens map[[sha256.Size]byte]int
	model  string
}

func New(provider Provider, key, model string) (*Proxy, error) {
	if key == "" {
		return nil, errors.New("model proxy: an API key is required")
	}
	if model == "" {
		return nil, errors.New("model proxy: a model is required")
	}
	upstream, err := url.Parse(provider.Upstream)
	if err != nil {
		return nil, fmt.Errorf("model proxy: %w", err)
	}

	p := &Proxy{provider: provider, key: key, model: model, tokens: map[[sha256.Size]byte]int{}}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = upstream.Scheme, upstream.Host, upstream.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = upstream.Path+pr.In.URL.Path, ""
			for _, h := range []string{"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie", "OpenAI-Organization", "OpenAI-Project"} {
				pr.Out.Header.Del(h)
			}
			provider.SetKey(pr.Out.Header, key)
		},
		// Stream server-sent events to the agent as they arrive.
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
				return errUpstreamRedirect
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
	token = tokenPrefix + hex.EncodeToString(raw[:])
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
