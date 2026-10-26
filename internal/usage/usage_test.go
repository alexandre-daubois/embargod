package usage

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrackAddsUp(t *testing.T) {
	ctx, total := Track(context.Background())

	Add(ctx, Usage{Requests: 1, InputTokens: 100, OutputTokens: 10})
	Add(ctx, Usage{Requests: 2, InputTokens: 50, OutputTokens: 5})

	require.Equal(t, Usage{Requests: 3, InputTokens: 150, OutputTokens: 15}, total())
}

func TestAddWithoutTrackIsIgnored(t *testing.T) {
	Add(context.Background(), Usage{Requests: 1})
}

func TestTrackedContextsAreIndependent(t *testing.T) {
	first, firstTotal := Track(context.Background())
	_, secondTotal := Track(context.Background())

	Add(first, Usage{Requests: 1})

	require.Equal(t, int64(1), firstTotal().Requests)
	require.Zero(t, secondTotal())
}

func TestLogValue(t *testing.T) {
	var logs bytes.Buffer

	slog.New(slog.NewTextHandler(&logs, nil)).Info("triaged", "usage", Usage{Requests: 2, InputTokens: 30, OutputTokens: 4})

	require.Contains(t, logs.String(), "usage.requests=2 usage.input_tokens=30 usage.output_tokens=4")
}

func TestNestedTracksAddUpInTheirParents(t *testing.T) {
	advisory, advisoryTotal := Track(context.Background())
	reader, readerTotal := Track(advisory)
	comparison, comparisonTotal := Track(advisory)
	Add(reader, Usage{Requests: 2})
	Add(comparison, Usage{Requests: 1})

	require.Equal(t, int64(2), readerTotal().Requests)
	require.Equal(t, int64(1), comparisonTotal().Requests, "a sibling track counted another one's usage")
	require.Equal(t, int64(3), advisoryTotal().Requests)
}
