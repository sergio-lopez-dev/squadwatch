// Package redact keeps secrets out of everything Squadwatch prints or stores.
package redact

import (
	"regexp"
	"strings"
)

var (
	// Well-known token prefixes (GitHub, GitLab, Slack, Anthropic, OpenAI,
	// Google, AWS, Hugging Face, npm, Stripe).
	tokenRe = regexp.MustCompile(`(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|sk-ant-|sk-proj-|sk-|AIza|AKIA|ASIA|hf_|npm_|sk_live_|rk_live_|pk_live_)[A-Za-z0-9_\-]{8,}`)
	urlCred = regexp.MustCompile(`(://[^/:@\s]+:)([^@\s/]+)(@)`)
	bearer  = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._~+/\-]{8,}=*)`)
	keyVal  = regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?key|token|secret|password|passwd|pwd)[A-Za-z0-9_\-]*["']?\s*[=:]\s*["']?)([^"'\s,}\]]{4,})`)
	keyName = regexp.MustCompile(`(?i)(key|token|secret|passw|pwd|auth|credential|bearer|cookie|session|private)`)
	refRe   = regexp.MustCompile(`^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{env:[^}]+\}|env:.+|op://.+|keyring:.+|\$\{input:[^}]+\})$`)
)

// Mask hides a secret, keeping only the last four characters of long values.
func Mask(v string) string {
	r := []rune(v)
	if len(r) <= 10 {
		return "••••"
	}
	return "••••" + string(r[len(r)-4:])
}

// Text redacts secrets that appear inside free text: config lines, URLs,
// command arguments.
func Text(s string) string {
	s = tokenRe.ReplaceAllStringFunc(s, Mask)
	s = urlCred.ReplaceAllString(s, "${1}••••${3}")
	s = bearer.ReplaceAllString(s, "${1}••••")
	s = keyVal.ReplaceAllStringFunc(s, func(m string) string {
		sub := keyVal.FindStringSubmatch(m)
		if strings.HasPrefix(sub[2], "$") || strings.HasPrefix(sub[2], "••••") {
			return m
		}
		return sub[1] + "••••"
	})
	return s
}

// LooksSecretKey reports whether a variable or header name suggests a secret.
func LooksSecretKey(k string) bool {
	return keyName.MatchString(k)
}

// TokenLike reports whether a value has the shape of a well-known token.
func TokenLike(v string) bool {
	return tokenRe.MatchString(v)
}

// LooksSecretValue reports whether a value looks like a credential on its own.
func LooksSecretValue(v string) bool {
	if TokenLike(v) {
		return true
	}
	if len(v) < 32 || strings.ContainsAny(v, " /.@:") {
		return false
	}
	var letters, digits int
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letters++
		case r == '-' || r == '_' || r == '=' || r == '+':
		default:
			return false
		}
	}
	return letters >= 8 && digits >= 4
}

// IsReference reports whether a value points at a secret stored elsewhere
// (an environment variable, a keyring entry, a VS Code input) instead of
// being the secret itself.
func IsReference(v string) bool {
	return refRe.MatchString(strings.TrimSpace(v))
}
