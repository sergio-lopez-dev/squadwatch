package i18n_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/sergio-lopez-dev/squadwatch/internal/i18n"
	"github.com/sergio-lopez-dev/squadwatch/internal/rules"
)

var (
	str   = `"((?:[^"\\]|\\.)*)"`
	tCall = regexp.MustCompile(`\bT\(\s*` + str)
	nCall = regexp.MustCompile(`\bN\([^,]+,\s*` + str + `\s*,\s*` + str)
)

// TestEveryMessageIsTranslated walks the source and fails on any T or N
// message without an English translation.
func TestEveryMessageIsTranslated(t *testing.T) {
	root := filepath.Join("..", "..")
	var missing []string
	check := func(file, lit string) {
		msg, err := strconv.Unquote(`"` + lit + `"`)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if !i18n.Has(msg) {
			missing = append(missing, file+": "+strconv.Quote(msg))
		}
	}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "i18n") {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, m := range tCall.FindAllStringSubmatch(string(b), -1) {
			check(p, m[1])
		}
		for _, m := range nCall.FindAllStringSubmatch(string(b), -1) {
			check(p, m[1])
			check(p, m[2])
		}
		return nil
	})
	for _, r := range rules.Catalog {
		for _, msg := range []string{r.Title, r.Why, r.Fix} {
			if !i18n.Has(msg) {
				missing = append(missing, "rules.Catalog "+r.ID+": "+strconv.Quote(msg))
			}
		}
	}
	for _, m := range missing {
		t.Error("sin traducción: " + m)
	}
}

func TestFormatsMatch(t *testing.T) {
	verbs := regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)
	for es, en := range i18n.Export() {
		a, b := verbs.FindAllString(es, -1), verbs.FindAllString(en, -1)
		if strings.Join(a, " ") != strings.Join(b, " ") {
			t.Errorf("los verbos no coinciden: %q → %q", es, en)
		}
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]i18n.Lang{"es_ES.UTF-8": i18n.ES, "en_GB": i18n.EN, "ES": i18n.ES, "en": i18n.EN} {
		if got, ok := i18n.Parse(in); !ok || got != want {
			t.Errorf("Parse(%q) = %q", in, got)
		}
	}
	if _, ok := i18n.Parse("fr"); ok {
		t.Error("fr no está soportado")
	}
	if i18n.EN.T("Crítico") != "Critical" || i18n.ES.T("Crítico") != "Crítico" {
		t.Error("T no traduce")
	}
	if i18n.EN.N(3, "1 alto", "%d altos") != "3 high" {
		t.Error("N no pluraliza")
	}
}
