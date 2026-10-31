package setup

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(b)
}

func TestAppCodeReturnsTheCodeOfTheRedirect(t *testing.T) {
	code, err := AppCode(t.Context(), "acme", map[string]any{"name": "acme-tamis"}, func(base string) {
		status, page := get(t, base)
		require.Equal(t, http.StatusOK, status)
		action := regexp.MustCompile(`action="https://github.com/organizations/acme/settings/apps/new\?state=([0-9a-f]{32})"`).FindStringSubmatch(page)
		require.NotNil(t, action, page)
		var manifest map[string]any
		require.NoError(t, json.Unmarshal([]byte(html.UnescapeString(regexp.MustCompile(`name="manifest" value="([^"]*)"`).FindStringSubmatch(page)[1])), &manifest))
		assert.Equal(t, map[string]any{"name": "acme-tamis", "redirect_url": base + "callback"}, manifest)

		status, _ = get(t, base+"callback?code=forged&state=0123")
		assert.Equal(t, http.StatusBadRequest, status, "a callback without the state is refused")
		status, _ = get(t, base+"callback?code=c0de&state="+action[1])
		assert.Equal(t, http.StatusOK, status)
	})

	require.NoError(t, err)
	require.Equal(t, "c0de", code)
}

func TestAppCodeStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	_, err := AppCode(ctx, "acme", nil, func(string) { cancel() })

	require.EqualError(t, err, "the GitHub App was not created")
}
