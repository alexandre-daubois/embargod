package budget

import (
	"context"
	"testing"
)

func TestNestedLimitsShareTheRunBudget(t *testing.T) {
	run := WithLimit(t.Context(), 3, 10)
	a := WithLimit(run, 2, 8)
	b := WithLimit(run, 2, 8)
	if !Take(a, 4) || !Take(b, 4) || Take(a, 3) || !Take(a, 2) || Take(b, 0) {
		t.Fatal("nested request/byte limits were not shared")
	}
}

func TestExhaustedChildDoesNotSpendParentBudget(t *testing.T) {
	parent := WithLimit(t.Context(), 1, 4)
	if Take(WithLimit(parent, 0, 4), 1) || !Take(parent, 4) || Take(parent, 0) {
		t.Fatal("an exhausted child spent the parent budget")
	}
}

func TestCanceledAndNegativeChargesFail(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if Take(ctx, 0) || Take(t.Context(), -1) || !Take(t.Context(), 0) {
		t.Fatal("invalid charge")
	}
}
