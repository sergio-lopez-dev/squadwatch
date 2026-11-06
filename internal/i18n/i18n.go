// Package i18n translates Squadwatch's user-facing text.
//
// Messages are written in Spanish in the source and used as keys, in the
// style of gettext: Lang.T("lee sin preguntar: %s", rule) returns the
// Spanish text in Spanish and looks up the English one in English. A test
// walks the source and fails if any message lacks an English translation.
package i18n

import (
	"fmt"
	"os"
	"strings"
)

// Lang is a supported language.
type Lang string

const (
	EN Lang = "en"
	ES Lang = "es"
)

// Parse reads "en", "es", "es_ES.UTF-8", "en-GB" and similar.
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "es"):
		return ES, true
	case strings.HasPrefix(s, "en"):
		return EN, true
	}
	return "", false
}

// FromEnv picks the language from SQUADWATCH_LANG, then the usual locale
// variables. English is the default.
func FromEnv() Lang {
	for _, v := range []string{"SQUADWATCH_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if l, ok := Parse(os.Getenv(v)); ok {
			return l
		}
	}
	return EN
}

// T translates a Spanish source message and formats it with args.
func (l Lang) T(msg string, args ...any) string {
	if l != ES {
		if t, ok := en[msg]; ok {
			msg = t
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// N picks the singular or the plural message. The plural takes the number
// as its first argument (%d).
func (l Lang) N(n int, one, many string) string {
	if n == 1 {
		return l.T(one)
	}
	return l.T(many, n)
}

// Has reports whether a source message has an English translation.
func Has(msg string) bool {
	_, ok := en[msg]
	return ok
}

// Export returns a copy of the English catalog, for tests.
func Export() map[string]string {
	out := make(map[string]string, len(en))
	for k, v := range en {
		out[k] = v
	}
	return out
}
