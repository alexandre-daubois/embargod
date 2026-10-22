// Package engine runs the tool-use loop against an LLM provider until the model submits its report.
package engine

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/alexandre-daubois/advisory-triage/internal/tools"
)

const (
	maxTurns = 40
	nudge    = "Submit your findings now with the " + tools.Submit + " tool."
)

var ErrNoReport = errors.New("the model did not submit a report")

type Engine interface {
	// Run returns the raw input the model passed to the tools.Submit tool, which ts must contain.
	Run(ctx context.Context, system, prompt string, ts []tools.Tool) (json.RawMessage, error)
}
