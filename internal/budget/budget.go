// Package budget bounds provider requests across all agents and comparators in a run.
package budget

import (
	"context"
	"sync"
)

type limit struct {
	mu              sync.Mutex
	requests, bytes int
	parent          *limit
}

type key struct{}

// WithLimit adds a budget without discarding the enclosing run's budget.
func WithLimit(ctx context.Context, requests, bytes int) context.Context {
	parent, _ := ctx.Value(key{}).(*limit)
	return context.WithValue(ctx, key{}, &limit{requests: requests, bytes: bytes, parent: parent})
}

// Take charges the entire request, including conversation history, before contacting the provider.
func Take(ctx context.Context, bytes int) bool {
	if ctx.Err() != nil || bytes < 0 {
		return false
	}
	l, _ := ctx.Value(key{}).(*limit)
	return l.take(bytes)
}

func (l *limit) take(bytes int) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.requests <= 0 || bytes > l.bytes || !l.parent.take(bytes) {
		return false
	}
	l.requests--
	l.bytes -= bytes
	return true
}
