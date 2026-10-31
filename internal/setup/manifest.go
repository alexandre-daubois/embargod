package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
)

var manifestPage = template.Must(template.New("manifest").Parse(`<!doctype html>
<form method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<button type="submit">Create the GitHub App on GitHub</button>
</form>
<script>document.forms[0].submit()</script>
`))

// AppCode registers a GitHub App of org from manifest through the browser and returns the code GitHub redirects
// back with. GitHub only takes a manifest posted by the browser of a signed-in owner, so a local page posts it.
func AppCode(ctx context.Context, org string, manifest map[string]any, open func(string)) (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	b := make([]byte, 16)
	rand.Read(b)
	state, base := hex.EncodeToString(b), "http://"+l.Addr().String()
	m := map[string]any{"redirect_url": base + "/callback"}
	for k, v := range manifest {
		m[k] = v
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	action := fmt.Sprintf("https://github.com/organizations/%s/settings/apps/new?state=%s", url.PathEscape(org), state)

	codes := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		manifestPage.Execute(w, map[string]string{"Action": action, "Manifest": string(data)})
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		// Only GitHub knows the state, so another local page cannot hand over a code of its own.
		if r.URL.Query().Get("state") != state || r.URL.Query().Get("code") == "" {
			http.Error(w, "unexpected callback", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "The GitHub App is created, you can close this tab.")
		select {
		case codes <- r.URL.Query().Get("code"):
		default:
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	open(base + "/")
	select {
	case code := <-codes:
		return code, nil
	case <-ctx.Done():
		return "", errors.New("the GitHub App was not created")
	}
}
