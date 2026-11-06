package detect

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/mcpcat"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/redact"
)

// parseServers reads an MCP server map in any of the common formats:
// Claude/Cursor/Gemini/Windsurf ("mcpServers"), VS Code ("servers") and
// Codex (TOML [mcp_servers.NAME]).
func parseServers(m map[string]any, d *doc, scope string) []model.MCPServer {
	var out []model.MCPServer
	for _, name := range sortedKeys(m) {
		sm, ok := m[name].(map[string]any)
		if !ok {
			continue
		}
		s := model.MCPServer{
			Name:  name,
			Scope: scope,
			Ref:   d.ref(`"`+name+`"`, "[mcp_servers."+name+"]", `[mcp_servers."`+name+`"]`, name+" ="),
		}
		s.Command = getStr(sm, "command")
		s.Args = getStrSlice(sm, "args")
		s.URL = first(getStr(sm, "url"), getStr(sm, "serverUrl"), getStr(sm, "httpUrl"))
		typ := strings.ToLower(first(getStr(sm, "type"), getStr(sm, "transport")))
		switch {
		case s.URL != "" && typ == "sse":
			s.Transport = "sse"
		case s.URL != "":
			s.Transport = "http"
		default:
			s.Transport = "stdio"
		}
		if v, ok := sm["enabled"].(bool); ok && !v {
			s.Disabled = true
		}
		if getBool(sm, "disabled") {
			s.Disabled = true
		}
		if getBool(sm, "trust") || len(getSlice(sm, "autoApprove")) > 0 || len(getSlice(sm, "alwaysAllow")) > 0 {
			s.AutoApproved = true
		}

		raw := map[string]bool{}
		env := getMap(sm, "env")
		for _, k := range sortedKeys(env) {
			s.EnvKeys = append(s.EnvKeys, k)
			addSecret(&s, d, raw, k, anyString(env[k]), "variable de entorno")
		}
		for _, hk := range []string{"headers", "http_headers"} {
			h := getMap(sm, hk)
			for _, k := range sortedKeys(h) {
				addSecret(&s, d, raw, k, anyString(h[k]), "cabecera HTTP")
			}
		}
		for _, k := range []string{"bearer_token", "apiKey", "api_key", "token"} {
			if v := getStr(sm, k); v != "" {
				addSecret(&s, d, raw, k, v, "campo")
			}
		}
		argSecrets(&s, d, raw)
		urlSecrets(&s, d, raw, s.URL, "URL")
		for _, a := range s.Args {
			if strings.Contains(a, "://") {
				urlSecrets(&s, d, raw, a, "argumento")
			}
		}

		mcpcat.Classify(&s)
		analyzePin(&s)

		// Never keep raw secrets in the model.
		for i, a := range s.Args {
			for sec := range raw {
				a = strings.ReplaceAll(a, sec, redact.Mask(sec))
			}
			s.Args[i] = redact.Text(a)
		}
		for sec := range raw {
			s.URL = strings.ReplaceAll(s.URL, sec, redact.Mask(sec))
		}
		s.URL = redact.Text(s.URL)
		out = append(out, s)
	}
	return out
}

func looksPath(v string) bool {
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "./") || filepath.Ext(v) == ".json"
}

func addSecret(s *model.MCPServer, d *doc, raw map[string]bool, key, val, where string) {
	v := strings.TrimSpace(val)
	if v == "" || redact.IsReference(v) || looksPath(v) || strings.Contains(v, "${") {
		return
	}
	if !redact.LooksSecretKey(key) && !redact.LooksSecretValue(v) {
		return
	}
	if lower := strings.ToLower(v); lower == "true" || lower == "false" {
		return
	}
	raw[v] = true
	s.Secrets = append(s.Secrets, model.Secret{Key: key, Masked: redact.Mask(v), Where: where, Line: d.line(v)})
}

func argSecrets(s *model.MCPServer, d *doc, raw map[string]bool) {
	for i, a := range s.Args {
		if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") && redact.LooksSecretKey(k) {
			addSecret(s, d, raw, k, v, "argumento")
			continue
		}
		if strings.HasPrefix(a, "-") && redact.LooksSecretKey(a) && i+1 < len(s.Args) && !strings.HasPrefix(s.Args[i+1], "-") {
			addSecret(s, d, raw, a, s.Args[i+1], "argumento")
			continue
		}
		if redact.TokenLike(a) {
			addSecret(s, d, raw, "argumento", a, "argumento")
		}
	}
}

func urlSecrets(s *model.MCPServer, d *doc, raw map[string]bool, rawURL, where string) {
	if rawURL == "" {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	if pw, ok := u.User.Password(); ok && pw != "" && !redact.IsReference(pw) {
		raw[pw] = true
		s.Secrets = append(s.Secrets, model.Secret{Key: "contraseña en " + where, Masked: redact.Mask(pw), Where: where, Line: d.line(pw)})
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if redact.LooksSecretKey(k) {
				addSecret(s, d, raw, k, v, where)
			}
		}
	}
}

// analyzePin decides whether the code an MCP server runs is pinned to a version.
func analyzePin(s *model.MCPServer) {
	if s.URL != "" {
		s.Pin, s.Pinned = "remoto", true
		return
	}
	args := s.Args
	switch filepath.Base(s.Command) {
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			args = args[1:]
		} else {
			s.Pin, s.Pinned = "local", true
			return
		}
		fallthrough
	case "npx", "bunx", "pnpx":
		pkg := npxPackage(args)
		ver := npmVersion(pkg)
		switch {
		case pkg == "":
			s.Pin = "desconocido"
		case ver == "":
			s.Pin = "sin fijar"
		case ver == "latest" || ver == "next":
			s.Pin = "@" + ver
		default:
			s.Pin, s.Pinned = ver, true
		}
	case "uvx", "pipx":
		if len(args) > 0 && args[0] == "run" {
			args = args[1:]
		}
		pkg := firstPositional(args, map[string]bool{"--from": true, "--with": true, "--python": true, "-p": true})
		if i := indexOf(args, "--from"); i >= 0 && i+1 < len(args) {
			pkg = args[i+1]
		}
		switch {
		case pkg == "":
			s.Pin = "desconocido"
		case strings.Contains(pkg, "=="):
			s.Pin, s.Pinned = strings.SplitN(pkg, "==", 2)[1], true
		case strings.Contains(pkg, "@") && !strings.HasSuffix(pkg, "@latest"):
			s.Pin, s.Pinned = strings.SplitN(pkg, "@", 2)[1], true
		default:
			s.Pin = "sin fijar"
		}
	case "docker", "podman":
		img := dockerImage(args)
		switch {
		case img == "":
			s.Pin = "desconocido"
		case strings.Contains(img, "@sha256:"):
			s.Pin, s.Pinned = "digest", true
		case strings.Contains(img[strings.LastIndex(img, "/")+1:], ":") && !strings.HasSuffix(img, ":latest"):
			s.Pin = "tag sin digest"
		default:
			s.Pin = "sin fijar"
		}
	default:
		s.Pin, s.Pinned = "local", true
	}
}

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func firstPositional(args []string, withValue map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if withValue[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func npxPackage(args []string) string {
	if i := indexOf(args, "-p"); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	if i := indexOf(args, "--package"); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--package=") {
			return strings.TrimPrefix(a, "--package=")
		}
	}
	return firstPositional(args, map[string]bool{"-c": true, "--call": true})
}

// npmVersion extracts the version from "pkg@1.2.3" or "@scope/pkg@1.2.3".
func npmVersion(pkg string) string {
	start := 0
	if strings.HasPrefix(pkg, "@") {
		start = 1
	}
	if i := strings.Index(pkg[start:], "@"); i >= 0 {
		return pkg[start+i+1:]
	}
	return ""
}

func dockerImage(args []string) string {
	i := indexOf(args, "run")
	if i < 0 {
		return ""
	}
	withValue := map[string]bool{"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true, "-p": true,
		"--publish": true, "--network": true, "--entrypoint": true, "-w": true, "--workdir": true, "-u": true,
		"--user": true, "--env-file": true, "--mount": true, "--platform": true, "-l": true, "--label": true}
	return firstPositional(args[i+1:], withValue)
}
