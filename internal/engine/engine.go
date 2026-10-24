// Package engine runs the tool-use loop against an LLM provider until the model submits its report.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/alexandre-daubois/tamis/internal/budget"
	"github.com/alexandre-daubois/tamis/internal/tools"
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

// WithRequestLimit shares one provider-request budget across every model call made with ctx.
func WithRequestLimit(ctx context.Context, n int) context.Context {
	return budget.WithLimit(ctx, n, 8<<20)
}

func takeRequest(ctx context.Context, params any) bool {
	body, err := json.Marshal(params)
	return err == nil && len(body) <= 1<<20 && budget.Take(ctx, len(body))
}
