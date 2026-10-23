// Package modelproxy keeps the model API key on the host. A sandboxed agent gets a token that is only
// good for this proxy, which swaps it for the real key on a fixed list of routes and forwards the request.
// Adapted from scrutineer's internal/worker/model_proxy.go.
package modelproxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
)

const (
	// PathPrefix is where the proxy serves, the agent's base URL ends with it.
	PathPrefix = "/model-proxy"
	// maxBody caps a forwarded request so a hostile agent cannot make the host buffer unbounded data.
	maxBody     = 32 << 20
	tokenPrefix = "embargod-"
)

var errUpstreamRedirect = errors.New("model proxy: upstream redirect refused")

// Provider describes one model API: where it lives, which routes an agent may call and how the key is sent.
type Provider struct {
	Upstream string
	Routes   func(method, route string) bool
	SetKey   func(h http.Header, key string)
}

var Anthropic = Provider{
	Upstream: "https://api.anthropic.com",
	Routes: func(method, route string) bool {
		switch {
		case method == http.MethodPost:
			return route == "/v1/messages" || route == "/v1/messages/count_tokens"
		case method == http.MethodGet:
			return route == "/v1/models" || modelRoute(route)
		default:
			return false
		}
	},
	SetKey: func(h http.Header, key string) { h.Set("X-Api-Key", key) },
}

var OpenAI = Provider{
	Upstream: "https://api.openai.com",
	Routes: func(method, route string) bool {
		switch {
		case method == http.MethodPost:
			return route == "/v1/responses"
		case method == http.MethodGet:
			return route == "/v1/models" || modelRoute(route)
		default:
			return false
		}
	},
	SetKey: func(h http.Header, key string) { h.Set("Authorization", "Bearer "+key) },
}

func modelRoute(route string) bool {
	id, ok := strings.CutPrefix(route, "/v1/models/")

	return ok && id != "" && !strings.Contains(id, "/")
}

type Proxy struct {
	provider Provider
	key      string
	proxy    *httputil.ReverseProxy

	mu     sync.RWMutex
	tokens map[[sha256.Size]byte]bool
}

func New(provider Provider, key string) (*Proxy, error) {
	if key == "" {
		return nil, errors.New("model proxy: an API key is required")
	}
	upstream, err := url.Parse(provider.Upstream)
	if err != nil {
		return nil, fmt.Errorf("model proxy: %w", err)
	}

	p := &Proxy{provider: provider, key: key, tokens: map[[sha256.Size]byte]bool{}}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = upstream.Scheme, upstream.Host, upstream.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = upstream.Path+pr.In.URL.Path, ""
			for _, h := range []string{"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie"} {
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
	p.tokens[sum] = true
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
	if r.URL.RawPath != "" || path.Clean(route) != route || !p.provider.Routes(r.Method, route) {
		http.Error(w, "route not permitted", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
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
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.tokens[sum]
}
