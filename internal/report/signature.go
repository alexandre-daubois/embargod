package report

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const signaturePrefix = "\n<!-- embargod-signature:v1:"

// Sign binds the entire comment to the repository, advisory and analysed revision.
func Sign(body, repository, advisory, revision string, key ed25519.PrivateKey) string {
	body += "\n_Signed by Embargod. Verify the raw Markdown with the security team's trusted public key; the canonical report is in its private workflow artifacts._\n"
	signature := ed25519.Sign(key, signedMessage(body, repository, advisory, revision))
	return body + signaturePrefix + revision + ":" + base64.StdEncoding.EncodeToString(signature) + " -->\n"
}

// Verify requires a public key from trusted configuration, never from the comment itself.
func Verify(body, repository, advisory string, key ed25519.PublicKey) (string, bool) {
	content, footer, ok := strings.Cut(body, signaturePrefix)
	if !ok || len(key) != ed25519.PublicKeySize {
		return "", false
	}
	footer, ok = strings.CutSuffix(footer, " -->\n")
	if !ok {
		return "", false
	}
	revision, encoded, ok := strings.Cut(footer, ":")
	digest, err := hex.DecodeString(revision)
	if !ok || err != nil || len(digest) != 32 {
		return "", false
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	return revision, err == nil && base64.StdEncoding.EncodeToString(signature) == encoded && ed25519.Verify(key, signedMessage(content, repository, advisory, revision), signature)
}

func signedMessage(body, repository, advisory, revision string) []byte {
	return []byte("embargod-comment-v1\x00" + strings.ToLower(repository) + "\x00" + strings.ToLower(advisory) + "\x00" + revision + "\x00" + body)
}
