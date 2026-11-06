package jsonc

import (
	"encoding/json"
	"testing"
)

func TestStrip(t *testing.T) {
	in := `{
  // line comment
  "url": "https://example.com/a//b", /* block
  comment */
  "list": [1, 2, 3,],
  "s": "has // inside and \" quote",
}`
	var v map[string]any
	if err := json.Unmarshal(Strip([]byte(in)), &v); err != nil {
		t.Fatalf("JSONC no válido tras Strip: %v\n%s", err, Strip([]byte(in)))
	}
	if v["url"] != "https://example.com/a//b" {
		t.Errorf("url alterada: %v", v["url"])
	}
	if v["s"] != `has // inside and " quote` {
		t.Errorf("cadena alterada: %v", v["s"])
	}
	if len(v["list"].([]any)) != 3 {
		t.Errorf("lista alterada: %v", v["list"])
	}
}
