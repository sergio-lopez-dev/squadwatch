package detect

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/sysinfo"
)

// configDir is where Electron editors keep their user settings.
func (e *Env) configDir(app string) string {
	if e.GOOS == "darwin" {
		return e.p("Library", "Application Support", app)
	}
	return e.p(".config", app)
}

// autoKeys finds settings that let an agent act without confirmation.
var autoKeyRe = regexp.MustCompile(`(?i)(yolo|autorun|auto_run|autoapprove|autoaccept|auto-approve)`)

func flagAutoSettings(a *model.Agent, d *doc, fix string) bool {
	found := false
	walk(d.Data, "", func(path string, v any) {
		last := path[strings.LastIndex(path, ".")+1:]
		if autoKeyRe.MatchString(last) && truthy(v) && !strings.Contains(strings.ToLower(path), "allowlist") {
			found = true
			a.Settings = append(a.Settings, model.Setting{Key: path, Value: anyString(v), Ref: d.ref(last)})
			a.Flag("AGT-001", path+" = "+anyString(v), fix, d.ref(last))
		}
	})
	return found
}

func editorBase(e *Env, yolo bool, untr ...string) model.Trifecta {
	t := model.Trifecta{
		Priv: model.Yes, PrivWhy: []string{e.T("ficheros del proyecto")},
		Untr: model.Yes, UntrWhy: untr,
		Out: model.Partial, OutWhy: []string{e.T("la terminal pide confirmación")},
	}
	if yolo {
		t.Out, t.OutWhy = model.Yes, []string{e.T("terminal sin confirmación")}
	}
	return t
}

func detectCursor(e *Env) *model.Agent {
	home := e.p(".cursor")
	bin := e.which("cursor", "/opt/Cursor/cursor", "/usr/bin/cursor", "/Applications/Cursor.app")
	if !exists(home) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "cursor", Name: "Cursor", Kind: e.T("IDE con agente"), Binary: e.short(bin)}
	for _, pj := range []string{"/opt/Cursor/resources/app/package.json", "/usr/share/cursor/resources/app/package.json", "/Applications/Cursor.app/Contents/Resources/app/package.json"} {
		if v := packageVersion(pj); e.allowed(pj) && v != "" {
			a.Version = v
			break
		}
	}
	yolo := false
	if d, err := e.readJSON(filepath.Join(e.configDir("Cursor"), "User", "settings.json")); d != nil {
		a.Configs = append(a.Configs, d.Short)
		if err == nil {
			yolo = flagAutoSettings(a, d, e.T("Desactiva la ejecución automática y deja que la terminal pida confirmación."))
		}
	}
	if d, err := e.readJSON(filepath.Join(home, "mcp.json")); d != nil && err == nil {
		a.Configs = append(a.Configs, d.Short)
		a.MCP = e.parseServers(getMap(d.Data, "mcpServers"), d, e.T("usuario"))
	}
	if yolo {
		for i := range a.MCP {
			a.MCP[i].AutoApproved = true
		}
	}
	a.Mode = e.T("confirmación")
	if yolo {
		a.Mode = e.T("ejecución automática")
	}
	a.Extras = append(a.Extras, e.T("Cursor guarda parte de sus ajustes en una base de datos interna que Squadwatch aún no lee"))
	a.Base = editorBase(e, yolo, e.T("ficheros del repositorio"), e.T("web y documentación (@web, @docs)"))
	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		b := strings.ToLower(p.Base())
		return b == "cursor" || strings.Contains(strings.ToLower(p.Exe), "/cursor/cursor")
	})
	a.Running = len(a.PIDs) > 0
	return a
}

func detectVSCode(e *Env) *model.Agent {
	extDir := e.p(".vscode", "extensions")
	matches, _ := filepath.Glob(filepath.Join(extDir, "github.copilot-chat-*"))
	if len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	a := &model.Agent{ID: "copilot", Name: "VS Code + Copilot", Kind: e.T("Extensión de IDE"), Binary: e.short(e.which("code"))}
	a.Version = versionRe.FindString(filepath.Base(matches[len(matches)-1]))
	user := filepath.Join(e.configDir("Code"), "User")
	yolo := false
	if d, err := e.readJSON(filepath.Join(user, "settings.json")); d != nil {
		a.Configs = append(a.Configs, d.Short)
		if err == nil {
			yolo = flagAutoSettings(a, d, e.T("Pon chat.tools.autoApprove a false para que cada herramienta pida confirmación."))
			a.MCP = append(a.MCP, e.parseServers(getMap(getMap(d.Data, "mcp"), "servers"), d, e.T("usuario (settings.json)"))...)
		}
	}
	if d, err := e.readJSON(filepath.Join(user, "mcp.json")); d != nil && err == nil {
		a.Configs = append(a.Configs, d.Short)
		a.MCP = append(a.MCP, e.parseServers(getMap(d.Data, "servers"), d, e.T("usuario"))...)
	}
	if yolo {
		for i := range a.MCP {
			a.MCP[i].AutoApproved = true
		}
	}
	a.Mode = e.T("confirmación")
	if yolo {
		a.Mode = e.T("aprobación automática")
	}
	a.Base = editorBase(e, yolo, e.T("ficheros del repositorio"), e.T("herramienta fetch"))
	a.PIDs = e.running(func(p sysinfo.Proc) bool { return p.Base() == "code" })
	a.Running = len(a.PIDs) > 0
	return a
}

func detectWindsurf(e *Env) *model.Agent {
	dir := e.p(".codeium", "windsurf")
	bin := e.which("windsurf")
	if !exists(dir) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "windsurf", Name: "Windsurf", Kind: e.T("IDE con agente"), Binary: e.short(bin), Mode: e.T("confirmación")}
	if d, err := e.readJSON(filepath.Join(dir, "mcp_config.json")); d != nil && err == nil {
		a.Configs = append(a.Configs, d.Short)
		a.MCP = e.parseServers(getMap(d.Data, "mcpServers"), d, e.T("usuario"))
	}
	a.Base = editorBase(e, false, e.T("ficheros del repositorio"), e.T("búsqueda web"))
	a.PIDs = e.running(func(p sysinfo.Proc) bool { return strings.EqualFold(p.Base(), "windsurf") })
	a.Running = len(a.PIDs) > 0
	return a
}

func detectGemini(e *Env) *model.Agent {
	dir := e.p(".gemini")
	bin := e.which("gemini")
	if !exists(dir) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "gemini", Name: "Gemini CLI", Kind: e.T("CLI de código"), Binary: e.short(bin), Version: npmVersionFromBin(bin), Mode: e.T("confirmación")}
	yolo := false
	if d, err := e.readJSON(filepath.Join(dir, "settings.json")); d != nil {
		a.Configs = append(a.Configs, d.Short)
		if err == nil {
			yolo = flagAutoSettings(a, d, e.T("Quita el modo yolo y deja que la shell pida confirmación."))
			a.MCP = e.parseServers(getMap(d.Data, "mcpServers"), d, e.T("usuario"))
			if ex := getStrSlice(getMap(d.Data, "tools"), "exclude"); len(ex) > 0 {
				a.Settings = append(a.Settings, model.Setting{Key: "tools.exclude", Value: strings.Join(ex, ", "), Ref: d.ref("exclude")})
			}
		}
	}
	if yolo {
		a.Mode = "yolo"
		for i := range a.MCP {
			a.MCP[i].AutoApproved = true
		}
	}
	e.addInstr(a, filepath.Join(dir, "GEMINI.md"))
	a.Base = model.Trifecta{
		Priv: model.Yes, PrivWhy: []string{e.T("ficheros del proyecto")},
		Untr: model.Yes, UntrWhy: []string{e.T("búsqueda web y web_fetch"), e.T("ficheros del repositorio")},
		Out: model.Partial, OutWhy: []string{e.T("la shell pide confirmación")},
	}
	if yolo {
		a.Base.Out, a.Base.OutWhy = model.Yes, []string{e.T("shell sin confirmación (yolo)")}
	}
	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		return p.Base() == "gemini" || strings.Contains(p.Line(), "@google/gemini-cli")
	})
	a.Running = len(a.PIDs) > 0
	return a
}

func detectClaudeDesktop(e *Env) *model.Agent {
	cfg := filepath.Join(e.configDir("Claude"), "claude_desktop_config.json")
	bin := e.which("claude-desktop", "/usr/bin/claude-desktop", "/Applications/Claude.app")
	if !exists(cfg) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "claude-desktop", Name: "Claude Desktop", Kind: e.T("App de escritorio"), Binary: e.short(bin), Mode: e.T("confirmación por herramienta"), Sandbox: e.T("no aplica")}
	if d, err := e.readJSON(cfg); d != nil && err == nil {
		a.Configs = append(a.Configs, d.Short)
		a.MCP = e.parseServers(getMap(d.Data, "mcpServers"), d, e.T("usuario"))
	}
	a.Base = model.Trifecta{Priv: model.No, Untr: model.No, Out: model.No}
	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		l := p.Line()
		return strings.Contains(l, "claude-desktop") || strings.Contains(l, "Claude.app/Contents/MacOS")
	})
	a.Running = len(a.PIDs) > 0
	return a
}

func detectAider(e *Env) *model.Agent {
	bin := e.which("aider")
	conf := e.p(".aider.conf.yml")
	if bin == "" && !exists(conf) {
		return nil
	}
	a := &model.Agent{ID: "aider", Name: "Aider", Kind: e.T("CLI de código"), Binary: e.short(bin), Mode: e.T("confirma cada cambio")}
	yolo := false
	if raw, err := os.ReadFile(conf); err == nil {
		e.read[conf] = true
		a.Configs = append(a.Configs, e.short(conf))
		for i, ln := range strings.Split(string(raw), "\n") {
			k, v, ok := strings.Cut(ln, ":")
			if ok && strings.TrimSpace(k) == "yes-always" && truthy(strings.TrimSpace(v)) {
				yolo = true
				a.Mode = "yes-always"
				a.Flag("AGT-001", "yes-always: true", e.T("Quita yes-always para que Aider confirme cada acción."), model.Ref{File: e.short(conf), Line: i + 1})
			}
		}
	}
	a.Base = model.Trifecta{
		Priv: model.Yes, PrivWhy: []string{e.T("ficheros del repositorio")},
		Untr: model.Partial, UntrWhy: []string{e.T("URLs que añadas al chat")},
		Out: model.Partial, OutWhy: []string{e.T("comandos con confirmación")},
	}
	if yolo {
		a.Base.Out, a.Base.OutWhy = model.Yes, []string{"yes-always"}
	}
	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		return strings.Contains(p.Line(), "aider") && strings.Contains(p.Line(), "python")
	})
	a.Running = len(a.PIDs) > 0
	return a
}

func packageVersion(p string) string {
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if m := regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`).FindSubmatch(raw); m != nil {
		return string(m[1])
	}
	return ""
}
