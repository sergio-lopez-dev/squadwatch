package redact

import (
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	cases := []struct{ in, mustNot string }{
		{`"GITHUB_TOKEN": "` + "gh" + "p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + `"`, "A1b2C3d4E5f6"},
		{"postgresql://app:hunter2secret@localhost/app", "hunter2secret"},
		{"Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"},
		{`X-Goog-Api-Key = "` + "AI" + "zaSyD-abcdefghijklmnopqrstuvw" + `"`, "abcdefghijklmnop"},
		{"--api-key=" + "sk-" + "proj-abcdefghijklmnop", "abcdefghijklmnop"},
		{"password: correcthorsebattery", "correcthorsebattery"},
	}
	for _, c := range cases {
		if out := Text(c.in); strings.Contains(out, c.mustNot) {
			t.Errorf("Text(%q) = %q, sigue mostrando el secreto", c.in, out)
		}
	}
	if out := Text(`"token": "${GITHUB_TOKEN}"`); !strings.Contains(out, "${GITHUB_TOKEN}") {
		t.Errorf("una referencia a variable no es un secreto: %q", out)
	}
}

func TestMask(t *testing.T) {
	if Mask("short") != "••••" {
		t.Error("los valores cortos se ocultan del todo")
	}
	if got := Mask("gh" + "p_0123456789abcdef"); got != "••••cdef" {
		t.Errorf("Mask = %q", got)
	}
}

func TestIsReference(t *testing.T) {
	for _, v := range []string{"${GITHUB_TOKEN}", "$TOKEN", "{env:TOKEN}", "op://vault/item/field", "keyring:github", "${input:token}"} {
		if !IsReference(v) {
			t.Errorf("%q es una referencia", v)
		}
	}
	if IsReference("gh" + "p_realtoken") {
		t.Error("un token no es una referencia")
	}
}
