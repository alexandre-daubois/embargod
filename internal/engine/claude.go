package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/alexandre-daubois/advisory-triage/internal/tools"
)

const DefaultClaudeModel = "claude-opus-5-5"

type Claude struct {
	client anthropic.Client
	model  string
}

func NewClaude(apiKey, model string, opts ...option.RequestOption) *Claude {
	return &Claude{client: anthropic.NewClient(append([]option.RequestOption{option.WithAPIKey(apiKey)}, opts...)...), model: model}
}

func (c *Claude) Run(ctx context.Context, system, prompt string, ts []tools.Tool) (json.RawMessage, error) {
	defs := make([]anthropic.BetaToolUnionParam, 0, len(ts))
	for _, t := range ts {
		defs = append(defs, anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{
				Properties:  t.Properties,
				Required:    t.Required,
				ExtraFields: map[string]any{"additionalProperties": false},
			},
		}})
	}

	params := anthropic.BetaMessageNewParams{
		Model:        c.model,
		MaxTokens:    16000,
		System:       []anthropic.BetaTextBlockParam{{Text: system}},
		Messages:     []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt))},
		Tools:        defs,
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffortHigh},
		// Security reports can trip the cyber classifier, the server-side fallback re-serves refused requests.
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	}

	for range maxTurns {
		resp, err := c.client.Beta.Messages.New(ctx, params)
		if err != nil {
			return nil, err
		}
		if resp.StopReason == anthropic.BetaStopReasonRefusal {
			return nil, fmt.Errorf("the model refused: %s %s", resp.StopDetails.Category, resp.StopDetails.Explanation)
		}
		params.Messages = append(params.Messages, resp.ToParam())

		var results []anthropic.BetaContentBlockParamUnion
		for _, block := range resp.Content {
			use, ok := block.AsAny().(anthropic.BetaToolUseBlock)
			if !ok {
				continue
			}
			input := json.RawMessage(use.JSON.Input.Raw())
			if use.Name == tools.Submit {
				return input, nil
			}
			out, isError := tools.Call(ctx, ts, use.Name, input)
			results = append(results, anthropic.NewBetaToolResultBlock(use.ID, out, isError))
		}

		if len(results) == 0 {
			results = append(results, anthropic.NewBetaTextBlock(nudge))
		}
		params.Messages = append(params.Messages, anthropic.NewBetaUserMessage(results...))
	}

	return nil, ErrNoReport
}
