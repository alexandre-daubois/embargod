package report

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	revision := strings.Repeat("a", 64)
	body := Sign("verdict\n", "O/R", "GHSA-id", revision, key)
	if got, ok := Verify(body, "o/r", "ghsa-id", key.Public().(ed25519.PublicKey)); !ok || got != revision {
		t.Fatal("valid comment rejected")
	}
	for name, value := range map[string]string{
		"edited verdict":  strings.Replace(body, "verdict", "forged", 1),
		"edited revision": strings.Replace(body, revision, strings.Repeat("b", 64), 1),
		"unsigned":        "verdict\n",
		"trailing text":   body + "forged",
		"truncated":       body[:len(body)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := Verify(value, "o/r", "GHSA-id", key.Public().(ed25519.PublicKey)); ok {
				t.Fatal("forged comment accepted")
			}
		})
	}
	for _, scope := range [][2]string{{"other/repo", "GHSA-id"}, {"o/r", "GHSA-other"}} {
		if _, ok := Verify(body, scope[0], scope[1], key.Public().(ed25519.PublicKey)); ok {
			t.Fatal("cross-advisory replay accepted")
		}
	}
	if _, ok := Verify(body, "o/r", "GHSA-id", nil); ok {
		t.Fatal("missing key accepted")
	}
}

func FuzzSignature(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	body := Sign("verdict", "o/r", "GHSA-id", strings.Repeat("a", 64), key)
	f.Add(body)
	f.Add("unsigned")
	f.Fuzz(func(t *testing.T, value string) {
		if _, valid := Verify(value, "o/r", "GHSA-id", key.Public().(ed25519.PublicKey)); valid && value != body {
			t.Fatal("a modified signature was accepted")
		}
	})
}
