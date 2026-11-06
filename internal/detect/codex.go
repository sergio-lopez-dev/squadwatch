package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/sysinfo"
)

func detectCodex(e *Env) *model.Agent {
	dir := e.p(".codex")
	bin := e.which("codex")
	if !exists(dir) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "codex", Name: "Codex CLI", Kind: e.T("CLI de código"), Binary: e.short(bin), Version: npmVersionFromBin(bin)}

	cfg := filepath.Join(dir, "config.toml")
	d := &doc{Path: cfg, Short: e.short(cfg), Data: map[string]any{}}
	if raw, err := os.ReadFile(cfg); err == nil {
		e.read[cfg] = true
		d.Raw = raw
		a.Configs = append(a.Configs, d.Short)
		if _, err := toml.Decode(string(raw), &d.Data); err != nil {
			a.Extras = append(a.Extras, e.T("No se pudo leer %s: %s", d.Short, err.Error()))
		}
	}

	approval := getStr(d.Data, "approval_policy")
	sandbox := getStr(d.Data, "sandbox_mode")
	network := getBool(getMap(d.Data, "sandbox_workspace_write"), "network_access")
	a.Mode = "approval_policy = " + first(approval, e.T("on-request (por defecto)"))
	a.Sandbox = first(sandbox, e.T("read-only (por defecto)"))
	if approval != "" {
		a.Settings = append(a.Settings, model.Setting{Key: "approval_policy", Value: approval, Ref: d.ref("approval_policy")})
	}
	if sandbox != "" {
		a.Settings = append(a.Settings, model.Setting{Key: "sandbox_mode", Value: sandbox, Ref: d.ref("sandbox_mode")})
	}
	if network {
		a.Settings = append(a.Settings, model.Setting{Key: "sandbox_workspace_write.network_access", Value: "true", Ref: d.ref("network_access")})
	}
	checkCodexPolicy(e, a, d, approval, sandbox, "")
	profiles := getMap(d.Data, "profiles")
	for _, name := range sortedKeys(profiles) {
		pm := getMap(profiles, name)
		checkCodexPolicy(e, a, d, getStr(pm, "approval_policy"), getStr(pm, "sandbox_mode"), name)
	}

	a.MCP = e.parseServers(getMap(d.Data, "mcp_servers"), d, e.T("usuario"))
	if approval == "never" {
		for i := range a.MCP {
			a.MCP[i].AutoApproved = true
		}
	}

	trusted := 0
	prj := getMap(d.Data, "projects")
	e.addInstr(a, filepath.Join(dir, "AGENTS.md"))
	for _, p := range sortedKeys(prj) {
		if getStr(getMap(prj, p), "trust_level") == "trusted" {
			trusted++
			e.addInstr(a, filepath.Join(p, "AGENTS.md"))
		}
	}
	if trusted > 0 {
		a.Extras = append(a.Extras, e.N(trusted, "1 proyecto marcado como de confianza", "%d proyectos marcados como de confianza"))
	}

	web := getBool(getMap(d.Data, "tools"), "web_search") || getStr(d.Data, "web_search") == "live"
	a.Base = model.Trifecta{
		Priv: model.Yes, PrivWhy: []string{e.T("ficheros del workspace")},
		Untr: model.Yes, UntrWhy: []string{e.T("ficheros del repositorio (AGENTS.md, código)")},
	}
	if web {
		a.Base.UntrWhy = append(a.Base.UntrWhy, e.T("búsqueda web"))
	}
	open := sandbox == "danger-full-access" || network
	switch {
	case open && approval == "never":
		a.Base.Out, a.Base.OutWhy = model.Yes, []string{e.T("red disponible sin aprobación")}
	case open:
		a.Base.Out, a.Base.OutWhy = model.Partial, []string{e.T("red disponible, pide aprobación")}
	case approval == "never":
		a.Base.Out, a.Base.OutWhy = model.No, []string{e.T("sandbox sin red")}
	default:
		a.Base.Out, a.Base.OutWhy = model.Partial, []string{e.T("pide permiso para salir de la sandbox")}
	}

	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		return p.Base() == "codex" || strings.Contains(p.Line(), "@openai/codex")
	})
	a.Running = len(a.PIDs) > 0
	sort.Strings(a.Configs)
	return a
}

func checkCodexPolicy(e *Env, a *model.Agent, d *doc, approval, sandbox, profile string) {
	where := ""
	if profile != "" {
		where = e.T(" (perfil %s)", profile)
	}
	switch {
	case approval == "never" && sandbox == "danger-full-access":
		a.Flag("AGT-001", e.T("approval_policy = \"never\" y sandbox_mode = \"danger-full-access\"%s", where),
			e.T("Usa approval_policy = \"on-request\" y sandbox_mode = \"workspace-write\"."), d.ref("danger-full-access"))
	case sandbox == "danger-full-access":
		a.Flag("AGT-004", "sandbox_mode = \"danger-full-access\""+where,
			e.T("Usa sandbox_mode = \"workspace-write\"."), d.ref("danger-full-access"))
	case approval == "never":
		a.Flag("AGT-003", "approval_policy = \"never\""+where,
			e.T("Usa approval_policy = \"on-request\", al menos en repositorios que no son tuyos."), d.ref("approval_policy"))
	}
}

// npmVersionFromBin reads the version of a CLI installed with npm by
// following its symlink to the package directory.
func npmVersionFromBin(bin string) string {
	if bin == "" {
		return ""
	}
	target, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(target)
	for i := 0; i < 4; i++ {
		if raw, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
			var pkg struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &pkg) == nil && pkg.Version != "" {
				return pkg.Version
			}
		}
		dir = filepath.Dir(dir)
	}
	return versionRe.FindString(target)
}
