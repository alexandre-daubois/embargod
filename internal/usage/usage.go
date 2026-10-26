// Package usage adds up the model requests and tokens spent on one advisory, so a run can log what it cost.
package usage

import (
	"context"
	"log/slog"
	"sync"
)

// Usage counts billed requests. Input tokens include the cached ones, which providers bill at another rate.
type Usage struct {
	Requests     int64
	InputTokens  int64
	OutputTokens int64
}

func (u Usage) Plus(o Usage) Usage {
	return Usage{u.Requests + o.Requests, u.InputTokens + o.InputTokens, u.OutputTokens + o.OutputTokens}
}

func (u Usage) LogValue() slog.Value {
	return slog.GroupValue(slog.Int64("requests", u.Requests), slog.Int64("input_tokens", u.InputTokens), slog.Int64("output_tokens", u.OutputTokens))
}

type counter struct {
	mu     sync.Mutex
	total  Usage
	parent *counter
}

type key struct{}

// Track returns a context collecting what Add records with it, and a function reading the total. What it
// collects also adds up in the contexts tracked above it.
func Track(ctx context.Context) (context.Context, func() Usage) {
	parent, _ := ctx.Value(key{}).(*counter)
	c := &counter{parent: parent}

	return context.WithValue(ctx, key{}, c), func() Usage {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.total
	}
}

func Add(ctx context.Context, u Usage) {
	c, _ := ctx.Value(key{}).(*counter)
	for ; c != nil; c = c.parent {
		c.mu.Lock()
		c.total = c.total.Plus(u)
		c.mu.Unlock()
	}
}
