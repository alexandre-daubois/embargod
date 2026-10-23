// Package engine runs the tool-use loop against an LLM provider until the model submits its report.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/alexandre-daubois/embargod/internal/tools"
)

const (
	maxTurns        = 40
	maxOutputTokens = 16_000
	nudge           = "Submit your findings now with the " + tools.Submit + " tool."
)

var ErrNoReport = errors.New("the model did not submit a report")

func invalid(err error) string {
	return "error: the submission does not match the schema, fix it and submit again: " + err.Error()
}

// APIError keeps only the status code: provider errors embed the response body, which may echo the prompt.
type APIError struct {
	Provider string
	Status   int
}

func (e *APIError) Error() string {
	if e.Status == 0 {
		return e.Provider + ": request failed"
	}

	return fmt.Sprintf("%s: HTTP %d", e.Provider, e.Status)
}

// RefusalError keeps only the category: the explanation may paraphrase the report.
type RefusalError struct {
	Category string
}

func (e *RefusalError) Error() string {
	if e.Category == "" {
		return "the model refused"
	}

	return fmt.Sprintf("the model refused (category %q)", e.Category)
}

type Engine interface {
	// Run returns the raw input the model passed to the tools.Submit tool, which ts must contain.
	Run(ctx context.Context, system, prompt string, ts []tools.Tool) (json.RawMessage, error)
}

type requestLimit struct {
	mu        sync.Mutex
	remaining int
}

type requestLimitKey struct{}

// WithRequestLimit shares one provider-request budget across every model call made with ctx.
func WithRequestLimit(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, requestLimitKey{}, &requestLimit{remaining: n})
}

func takeRequest(ctx context.Context) bool {
	limit, ok := ctx.Value(requestLimitKey{}).(*requestLimit)
	if !ok {
		return true
	}
	limit.mu.Lock()
	defer limit.mu.Unlock()
	if limit.remaining == 0 {
		return false
	}
	limit.remaining--

	return true
}
