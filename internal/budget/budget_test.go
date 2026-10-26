package budget

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNestedLimitsShareTheRunBudget(t *testing.T) {
	run := WithLimit(t.Context(), 3, 10)
	a := WithLimit(run, 2, 8)
	b := WithLimit(run, 2, 8)
	require.True(t, Take(a, 4))
	require.True(t, Take(b, 4))
	require.False(t, Take(a, 3), "nested request/byte limits were not shared")
	require.True(t, Take(a, 2))
	require.False(t, Take(b, 0), "nested request/byte limits were not shared")
}

func TestExhaustedChildDoesNotSpendParentBudget(t *testing.T) {
	parent := WithLimit(t.Context(), 1, 4)
	require.False(t, Take(WithLimit(parent, 0, 4), 1))
	require.True(t, Take(parent, 4), "an exhausted child spent the parent budget")
	require.False(t, Take(parent, 0))
}

func TestCanceledAndNegativeChargesFail(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, Take(ctx, 0), "invalid charge")
	require.False(t, Take(t.Context(), -1), "invalid charge")
	require.True(t, Take(t.Context(), 0))
}

func TestHasChecksEveryLevelWithoutSpending(t *testing.T) {
	run := WithLimit(t.Context(), 3, 10)
	advisory := WithLimit(run, 2, 8)
	require.True(t, Has(advisory, 2, 8))
	require.True(t, Take(advisory, 0), "Has spent the budget")
	require.False(t, Has(advisory, 2, 0), "the advisory limit was ignored")
	require.False(t, Has(WithLimit(run, 5, 20), 3, 11), "the run limit was ignored")
	require.True(t, Has(t.Context(), 1000, 1<<30), "no limit refused a request")
}
