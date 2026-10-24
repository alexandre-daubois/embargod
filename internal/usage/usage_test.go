package usage

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestTrackAddsUp(t *testing.T) {
	ctx, total := Track(context.Background())

	Add(ctx, Usage{Requests: 1, InputTokens: 100, OutputTokens: 10})
	Add(ctx, Usage{Requests: 2, InputTokens: 50, OutputTokens: 5})

	if got := total(); got != (Usage{Requests: 3, InputTokens: 150, OutputTokens: 15}) {
		t.Fatalf("got %+v", got)
	}
}

func TestAddWithoutTrackIsIgnored(t *testing.T) {
	Add(context.Background(), Usage{Requests: 1})
}

func TestTrackedContextsAreIndependent(t *testing.T) {
	first, firstTotal := Track(context.Background())
	_, secondTotal := Track(context.Background())

	Add(first, Usage{Requests: 1})

	if firstTotal().Requests != 1 || secondTotal() != (Usage{}) {
		t.Fatalf("got %+v and %+v", firstTotal(), secondTotal())
	}
}

func TestLogValue(t *testing.T) {
	var logs bytes.Buffer

	slog.New(slog.NewTextHandler(&logs, nil)).Info("triaged", "usage", Usage{Requests: 2, InputTokens: 30, OutputTokens: 4})

	if want := "usage.requests=2 usage.input_tokens=30 usage.output_tokens=4"; !strings.Contains(logs.String(), want) {
		t.Fatalf("logs miss %q:\n%s", want, logs.String())
	}
}
