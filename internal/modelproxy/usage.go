package modelproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"github.com/php/tamis/internal/usage"
)

// usageReader reads the tokens a model response reports, as one JSON body or as server-sent events, while the
// response is relayed. Streamed counters are cumulative, so each one keeps its highest value.
type usageReader struct {
	io.ReadCloser
	stream bool
	buf    []byte
	tokens usage.Usage
	done   func(usage.Usage)
	once   sync.Once
}

func (u *usageReader) Read(b []byte) (int, error) {
	n, err := u.ReadCloser.Read(b)
	u.buf = append(u.buf, b[:n]...)
	for u.stream {
		line, rest, ok := bytes.Cut(u.buf, []byte("\n"))
		if !ok {
			break
		}
		u.observe(line)
		u.buf = rest
	}
	// The usage of a response larger than any model answer is lost rather than buffered.
	if len(u.buf) > maxBody {
		u.buf = nil
	}
	if err != nil {
		u.finish()
	}

	return n, err
}

func (u *usageReader) Close() error {
	u.finish()

	return u.ReadCloser.Close()
}

func (u *usageReader) finish() {
	u.once.Do(func() {
		u.observe(u.buf)
		u.tokens.Requests = 1
		u.done(u.tokens)
	})
}

type reported struct {
	InputTokens   int64 `json:"input_tokens"`
	CacheCreation int64 `json:"cache_creation_input_tokens"`
	CacheRead     int64 `json:"cache_read_input_tokens"`
	OutputTokens  int64 `json:"output_tokens"`
}

// observe looks where Anthropic and the Responses API put the usage: at the top of a message or of a
// message_delta event, under message in message_start and under response in response.completed.
func (u *usageReader) observe(data []byte) {
	if !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte("data:"))
	var event struct {
		Usage   *reported `json:"usage"`
		Message struct {
			Usage *reported `json:"usage"`
		} `json:"message"`
		Response struct {
			Usage *reported `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &event) != nil {
		return
	}
	for _, r := range []*reported{event.Usage, event.Message.Usage, event.Response.Usage} {
		if r == nil {
			continue
		}
		// Anthropic leaves cached tokens out of input_tokens, OpenAI counts them in.
		u.tokens.InputTokens = max(u.tokens.InputTokens, r.InputTokens+r.CacheCreation+r.CacheRead)
		u.tokens.OutputTokens = max(u.tokens.OutputTokens, r.OutputTokens)
	}
}
