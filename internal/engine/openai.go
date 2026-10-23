package engine

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"

	"github.com/alexandre-daubois/embargod/internal/tools"
)

const DefaultOpenAIModel = shared.ChatModelGPT5_5

type OpenAI struct {
	client openai.Client
	model  string
}

func NewOpenAI(apiKey, model string, opts ...option.RequestOption) *OpenAI {
	return &OpenAI{client: openai.NewClient(append([]option.RequestOption{option.WithAPIKey(apiKey)}, opts...)...), model: model}
}

func (o *OpenAI) Run(ctx context.Context, system, prompt string, ts []tools.Tool) (json.RawMessage, error) {
	defs := make([]openai.ChatCompletionToolUnionParam, 0, len(ts))
	for _, t := range ts {
		schema := shared.FunctionParameters{"type": "object", "properties": map[string]any{}, "required": []string{}, "additionalProperties": false}
		if t.Properties != nil {
			schema["properties"] = t.Properties
		}
		if t.Required != nil {
			schema["required"] = t.Required
		}
		defs = append(defs, openai.ChatCompletionFunctionTool(shared.FunctionDefinitionParam{
			Name:        t.Name,
			Description: openai.String(t.Description),
			Parameters:  schema,
		}))
	}

	params := openai.ChatCompletionNewParams{
		Model:               o.model,
		Messages:            []openai.ChatCompletionMessageParamUnion{openai.SystemMessage(system), openai.UserMessage(prompt)},
		Tools:               defs,
		MaxCompletionTokens: openai.Int(maxOutputTokens),
		ReasoningEffort:     shared.ReasoningEffortHigh,
	}

	for range maxTurns {
		if !takeRequest(ctx) {
			return nil, ErrNoReport
		}
		resp, err := o.client.Chat.Completions.New(ctx, params)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			apiErr := &APIError{Provider: "openai"}
			if sdkErr := (*openai.Error)(nil); errors.As(err, &sdkErr) {
				apiErr.Status = sdkErr.StatusCode
			}
			return nil, apiErr
		}
		if len(resp.Choices) == 0 {
			return nil, errors.New("empty completion")
		}
		msg := resp.Choices[0].Message
		if msg.Refusal != "" {
			return nil, &RefusalError{}
		}
		params.Messages = append(params.Messages, msg.ToParam())

		for _, call := range msg.ToolCalls {
			input := json.RawMessage(call.Function.Arguments)
			if call.Function.Name == tools.Submit {
				err := tools.Validate(ctx, ts, input)
				if err == nil {
					return input, nil
				}
				params.Messages = append(params.Messages, openai.ToolMessage(invalid(err), call.ID))
				continue
			}
			out, _ := tools.Call(ctx, ts, call.Function.Name, input)
			params.Messages = append(params.Messages, openai.ToolMessage(out, call.ID))
		}

		if len(msg.ToolCalls) == 0 {
			params.Messages = append(params.Messages, openai.UserMessage(nudge))
		}
	}

	return nil, ErrNoReport
}
