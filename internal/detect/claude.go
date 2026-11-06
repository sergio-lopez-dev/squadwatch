package detect

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/redact"
	"github.com/sergio-lopez-dev/squadwatch/internal/sysinfo"
)

var (
	versionRe   = regexp.MustCompile(`\d+\.\d+\.\d+`)
	netToolRule = regexp.MustCompile(`(?i)^Bash\((sudo )?(curl|wget|nc|ncat|netcat|scp|sftp|ftp|rsync|ssh|telnet|http|https|xh|gh)\b`)
)

// shellWildcard reports rules that allow any shell command.
func shellWildcard(rule string) bool {
	switch strings.ReplaceAll(rule, " ", "") {
	case "Bash", "Bash(*)", "Bash(:*)", "Bash(**)":
		return true
	}
	return false
}

// networkWildcard reports rules that let the agent send arbitrary data out.
// An exact command such as Bash(curl -s https://example.com/) only allows
// that literal command, so it cannot be used to exfiltrate data; a rule
// with a wildcard such as Bash(curl *) can.
func networkWildcard(rule string) bool {
	if rule == "WebFetch" {
		return true
	}
	return netToolRule.MatchString(rule) && strings.Contains(rule, "*")
}

// arbitraryPrefix matches what comes before the wildcard in rules that let
// the agent run any program or any code: Bash(node -e ' *), Bash(bundle exec *).
var arbitraryPrefix = regexp.MustCompile(`(?i)^(sudo|env|xargs|nohup|nice|eval|exec|timeout( \S+)?|time|(ba|z|da)?sh( -[a-z]*c)?|(node|deno|bun)( -e| --eval| -p)?|(python3?|ruby|perl|php)( -[cer])?|bundle exec|npx( -y| --yes)?|pnpm dlx|bunx|uvx|uv run|pipx run|(docker|podman) (run|exec)|kubectl( \S+)* exec|(\S+/)?rails runner|(timeout \S+ )?(\S+/)?rails runner)$`)

// arbitraryCode reports Bash rules whose wildcard lets the agent choose the
// program or the code to run, which includes sending data anywhere.
func arbitraryCode(rule string) bool {
	if !strings.HasPrefix(rule, "Bash(") || !strings.Contains(rule, "*") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(rule, "Bash("), ")")
	prefix := strings.TrimRight(inner[:strings.Index(inner, "*")], " '\"")
	prefix = strings.TrimSuffix(prefix, ":")
	return arbitraryPrefix.MatchString(strings.TrimSpace(prefix))
}

// readsEverything reports Read rules that cover the whole home or disk.
func readsEverything(rule, home string) bool {
	if !strings.HasPrefix(rule, "Read(") {
		return false
	}
	path := strings.TrimSuffix(strings.TrimPrefix(rule, "Read("), ")")
	path = strings.TrimSuffix(strings.TrimSuffix(path, "**"), "/")
	switch {
	case path == "" || path == "/" || path == "~":
		return true
	case strings.HasPrefix(path, "//"):
		return filepath.Clean(path[1:]) == home
	}
	return false
}

// ruleNeedle is a prefix of a rule that can be found verbatim in the raw
// file, even when the rule has characters JSON escapes.
func ruleNeedle(rule string) string {
	if i := strings.IndexAny(rule, `"\`); i > 0 {
		rule = rule[:i]
	}
	return `"` + rule
}

// clip shortens long rules for display.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func detectClaudeCode(e *Env) *model.Agent {
	dir := e.p(".claude")
	state := e.p(".claude.json")
	bin := e.which("claude", e.p(".local", "bin", "claude"), e.p(".claude", "local", "claude"))
	if !exists(dir) && !exists(state) && bin == "" {
		return nil
	}
	a := &model.Agent{ID: "claude-code", Name: "Claude Code", Kind: e.T("CLI de código"), Binary: e.short(bin)}
	if bin != "" {
		if target, err := filepath.EvalSymlinks(bin); err == nil {
			a.Version = versionRe.FindString(target)
		}
	}

	var projects []string
	if st, err := e.readJSON(state); err == nil {
		a.Configs = append(a.Configs, st.Short)
		if a.Version == "" {
			a.Version = first(getStr(st.Data, "lastReleaseNotesSeen"), getStr(st.Data, "lastOnboardingVersion"))
		}
		a.MCP = append(a.MCP, e.parseServers(getMap(st.Data, "mcpServers"), st, e.T("usuario"))...)
		prj := getMap(st.Data, "projects")
		for _, p := range sortedKeys(prj) {
			pm, _ := prj[p].(map[string]any)
			sp := e.short(p)
			projects = append(projects, p)
			a.MCP = append(a.MCP, inProject(e.parseServers(getMap(pm, "mcpServers"), st, e.T("proyecto %s", sp)), sp)...)
			for _, t := range getStrSlice(pm, "allowedTools") {
				a.Perms = append(a.Perms, model.Perm{Rule: t, Kind: "allow", Project: sp, Ref: st.ref(ruleNeedle(t))})
			}
		}
	}

	type src struct{ path, scope, project string }
	files := []src{
		{"/etc/claude-code/managed-settings.json", e.T("gestionado"), ""},
		{filepath.Join(dir, "settings.json"), e.T("usuario"), ""},
		{filepath.Join(dir, "settings.local.json"), e.T("usuario"), ""},
	}
	for _, p := range projects {
		sp := e.short(p)
		files = append(files,
			src{filepath.Join(p, ".claude", "settings.json"), e.T("proyecto %s", sp), sp},
			src{filepath.Join(p, ".claude", "settings.local.json"), e.T("proyecto %s", sp), sp})
	}

	mode := ""
	bypassIn := map[string]bool{} // projects in bypass mode; "" means everywhere
	var sandboxIn []string        // projects with the Bash sandbox on; "" means everywhere
	for _, f := range files {
		d, err := e.readJSON(f.path)
		if d == nil {
			continue
		}
		a.Configs = append(a.Configs, d.Short)
		if err != nil {
			a.Extras = append(a.Extras, e.T("No se pudo leer %s", d.Short))
			continue
		}
		perms := getMap(d.Data, "permissions")
		for _, kind := range []string{"allow", "ask", "deny"} {
			for _, r := range getStrSlice(perms, kind) {
				a.Perms = append(a.Perms, model.Perm{Rule: r, Kind: kind, Project: f.project, Ref: d.ref(ruleNeedle(r))})
			}
		}
		if m := getStr(perms, "defaultMode"); m != "" {
			if f.project == "" {
				mode = m
			}
			a.Settings = append(a.Settings, model.Setting{Key: "permissions.defaultMode (" + f.scope + ")", Value: m, Ref: d.ref("defaultMode")})
			if m == "bypassPermissions" {
				bypassIn[f.project] = true
				a.Flag("AGT-001", "permissions.defaultMode = \"bypassPermissions\" ("+f.scope+")",
					e.T("Cambia defaultMode a \"acceptEdits\" o \"default\" y añade \"disableBypassPermissionsMode\": \"disable\"."), d.ref("defaultMode"))
			}
		}
		if getStr(perms, "disableBypassPermissionsMode") == "disable" {
			a.Settings = append(a.Settings, model.Setting{Key: "permissions.disableBypassPermissionsMode", Value: "disable", Ref: d.ref("disableBypassPermissionsMode")})
		}
		for _, dirx := range getStrSlice(perms, "additionalDirectories") {
			full := filepath.Clean(e.expand(dirx))
			if full == "/" || full == e.Home {
				a.Grants = append(a.Grants, model.Grant{Cap: model.Priv, Kind: "read", Reason: e.T("todo tu HOME (additionalDirectories)"), Project: f.project})
				a.Flag("SEC-001", e.T("permissions.additionalDirectories incluye %s (%s)", dirx, f.scope),
					e.T("Quita %s de additionalDirectories y añade solo las carpetas que necesites.", dirx), d.ref(dirx))
			}
		}
		if getBool(d.Data, "enableAllProjectMcpServers") {
			a.Flag("MCP-007", "enableAllProjectMcpServers = true ("+f.scope+")",
				e.T("Quita enableAllProjectMcpServers y aprueba cada servidor de .mcp.json uno a uno."), d.ref("enableAllProjectMcpServers"))
		}
		if sb := getMap(d.Data, "sandbox"); sb != nil {
			if getBool(sb, "enabled") {
				sandboxIn = append(sandboxIn, f.project)
				a.Mitigations = append(a.Mitigations, model.Mitigation{Covers: "out-bash", Project: f.project, Ref: d.ref("sandbox"),
					Detail: e.T("sandbox de Bash activada (%s): limita la red y los ficheros de los comandos", f.scope)})
			}
		}
		parseClaudeHooks(e, a, d, f.project)
	}

	for _, p := range projects {
		if d, err := e.readJSON(filepath.Join(p, ".mcp.json")); d != nil && err == nil {
			sp := e.short(p)
			a.Configs = append(a.Configs, d.Short)
			a.MCP = append(a.MCP, inProject(e.parseServers(getMap(d.Data, "mcpServers"), d, e.T("proyecto %s (.mcp.json)", sp)), sp)...)
		}
	}

	if mode == "" {
		mode = "default"
	}
	if n := len(bypassIn); n > 0 && !bypassIn[""] {
		mode += e.T(" · bypassPermissions en %s", e.N(n, "1 proyecto", "%d proyectos"))
	}
	a.Mode = mode
	everywhere := false
	for _, p := range sandboxIn {
		everywhere = everywhere || p == ""
	}
	switch {
	case everywhere:
		a.Sandbox = e.T("activada")
	case len(sandboxIn) > 0:
		a.Sandbox = e.T("activada solo en %s", strings.Join(unique(sandboxIn), ", "))
	default:
		a.Sandbox = e.T("desactivada")
	}

	// Instruction files, skills and subagents.
	e.addInstr(a, filepath.Join(dir, "CLAUDE.md"))
	for _, p := range projects {
		e.addInstr(a, filepath.Join(p, "CLAUDE.md"), filepath.Join(p, "CLAUDE.local.md"), filepath.Join(p, ".claude", "CLAUDE.md"))
	}
	md := func(n string) bool { return strings.HasSuffix(strings.ToLower(n), ".md") }
	skills := e.scanTree(a, filepath.Join(dir, "skills"), md, 400)
	agents := e.scanTree(a, filepath.Join(dir, "agents"), md, 200)
	plugins := e.scanTree(a, filepath.Join(dir, "plugins"), md, 600)
	if skills+agents+plugins > 0 {
		a.Extras = append(a.Extras, e.T("%d ficheros de skills, subagentes y plugins revisados", skills+agents+plugins))
	}

	// Which MCP servers run without asking, in the scope where they live.
	for i := range a.MCP {
		m := &a.MCP[i]
		for _, p := range a.Perms {
			if p.Kind == "allow" && (p.Project == "" || p.Project == m.Project) &&
				(p.Rule == "mcp__"+m.Name || strings.HasPrefix(p.Rule, "mcp__"+m.Name+"__")) {
				m.AutoApproved = true
			}
		}
		if bypassIn[""] || (m.Project != "" && bypassIn[m.Project]) {
			m.AutoApproved = true
		}
	}

	// Capabilities granted by the configuration, per project.
	for p := range bypassIn {
		a.Grants = append(a.Grants, model.Grant{Cap: model.Out, Kind: "mode", Reason: e.T("modo bypassPermissions"), Project: p})
	}
	seen := map[string]bool{}
	for _, p := range a.Perms {
		if p.Kind != "allow" || seen[p.Rule+"|"+p.File] {
			continue
		}
		seen[p.Rule+"|"+p.File] = true
		switch {
		case shellWildcard(p.Rule):
			a.Grants = append(a.Grants, model.Grant{Cap: model.Out, Kind: "bash", Reason: p.Rule, Project: p.Project})
			a.Flag("AGT-002", e.T("shell completa permitida sin preguntar: %s", p.Rule),
				e.T("Quita \"%s\" de allow y permite solo los comandos concretos que necesites.", p.Rule), p.Ref)
		case arbitraryCode(p.Rule):
			a.Grants = append(a.Grants, model.Grant{Cap: model.Out, Kind: "bash", Reason: clip(p.Rule, 60), Project: p.Project})
			a.Flag("AGT-002", e.T("puede ejecutar cualquier código sin preguntar: %s", clip(p.Rule, 90)),
				e.T("Sustituye \"%s\" por los comandos concretos que necesites, o muévela a ask.", clip(p.Rule, 60)), p.Ref)
		case readsEverything(p.Rule, e.Home):
			a.Grants = append(a.Grants, model.Grant{Cap: model.Priv, Kind: "read", Reason: e.T("todo tu HOME (%s)", p.Rule), Project: p.Project})
			detail := e.T("lee sin preguntar: %s", p.Rule)
			var sev model.Severity
			if ref, ok := denies(a, p.Project, ".ssh"); ok {
				sev = model.Med
				detail += e.T(" (mitigado en parte: hay reglas deny para ~/.ssh)")
				a.Mitigations = append(a.Mitigations, model.Mitigation{Covers: "read-secrets", Project: p.Project, Ref: ref,
					Detail: e.T("reglas deny protegen ~/.ssh aunque se pueda leer el resto del HOME")})
			}
			a.Flag("SEC-001", detail, e.T("Quita \"%s\" de allow y permite solo las carpetas de cada proyecto.", p.Rule), p.Ref)
			a.Signals[len(a.Signals)-1].Sev = sev
		case networkWildcard(p.Rule):
			kind := "bash"
			if p.Rule == "WebFetch" {
				kind = "web"
			}
			a.Grants = append(a.Grants, model.Grant{Cap: model.Out, Kind: kind, Reason: redact.Text(p.Rule), Project: p.Project})
			a.Flag("AGT-002", e.T("salida de red sin preguntar: %s", clip(p.Rule, 90)),
				e.T("Mueve \"%s\" de allow a ask para que pida confirmación.", clip(p.Rule, 60)), p.Ref)
		}
	}
	a.Base = model.Trifecta{
		Priv: model.Yes, PrivWhy: []string{e.T("ficheros del proyecto")},
		Untr: model.Yes, UntrWhy: []string{e.T("ficheros del repositorio"), e.T("WebFetch y WebSearch")},
		Out: model.Partial, OutWhy: []string{e.T("Bash y WebFetch piden confirmación")},
	}

	// Say plainly when guard hooks exist but none of them covers the way out.
	bashHooks, guarded := 0, false
	for _, h := range a.Hooks {
		if h.Event == "PreToolUse" && matcherCoversBash(h.Matcher) {
			bashHooks++
			guarded = guarded || h.Guards != ""
		}
	}
	if bashHooks > 0 && !guarded {
		a.Extras = append(a.Extras, e.T("%s antes de Bash, pero ninguno revisa comandos de red ni código arbitrario", e.N(bashHooks, "1 hook se ejecuta", "%d hooks se ejecutan")))
	}

	a.PIDs = e.running(func(p sysinfo.Proc) bool {
		l := p.Line()
		return p.Base() == "claude" || strings.Contains(l, "@anthropic-ai/claude-code") || strings.Contains(p.Exe, "/claude/versions/")
	})
	a.Running = len(a.PIDs) > 0
	sort.Strings(a.Configs)
	return a
}

// inProject marks servers as belonging to one project.
func inProject(servers []model.MCPServer, project string) []model.MCPServer {
	for i := range servers {
		servers[i].Project = project
	}
	return servers
}

// denies reports whether a deny rule that applies in the project protects
// a path containing needle.
func denies(a *model.Agent, project, needle string) (model.Ref, bool) {
	for _, p := range a.Perms {
		if p.Kind == "deny" && (p.Project == "" || p.Project == project) && strings.Contains(p.Rule, needle) {
			return p.Ref, true
		}
	}
	return model.Ref{}, false
}

// matcherCoversBash reports whether a hook matcher applies to the Bash tool.
func matcherCoversBash(m string) bool {
	if m == "" || m == "*" {
		return true
	}
	if re, err := regexp.Compile("^(?:" + m + ")$"); err == nil {
		return re.MatchString("Bash")
	}
	return strings.Contains(m, "Bash")
}

var (
	hookNetRe   = regexp.MustCompile(`(?i)\b(curl|wget|ncat|netcat|nc|scp|rsync|webfetch|exfil\w*)\b`)
	hookBlockRe = regexp.MustCompile(`(?i)(exit 2\b|permissionDecision|"decision"\s*:\s*"block"|deny)`)
)

// hookGuard reads a hook (its script, or the inline command) and says what
// it checks. It only recognises hooks that look for network commands and
// can block them; anything else returns "".
func hookGuard(e *Env, cmd string) string {
	text := cmd
	if target := hookTarget(e, cmd); target != "" {
		if fi, err := os.Stat(target); err == nil && fi.Size() < 256<<10 {
			if b, err := os.ReadFile(target); err == nil {
				e.read[target] = true
				text += "\n" + string(b)
			}
		}
	}
	if hookBlockRe.MatchString(text) && hookNetRe.MatchString(text) {
		return e.T("revisa comandos de red antes de ejecutarlos")
	}
	return ""
}

// parseClaudeHooks reads hooks: {Event: [{matcher, hooks: [{type, command}]}]}.
func parseClaudeHooks(e *Env, a *model.Agent, d *doc, project string) {
	hooks := getMap(d.Data, "hooks")
	for _, event := range sortedKeys(hooks) {
		groups, _ := hooks[event].([]any)
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			matcher := getStr(gm, "matcher")
			for _, h := range getSlice(gm, "hooks") {
				hm, _ := h.(map[string]any)
				cmd := getStr(hm, "command")
				if cmd == "" {
					continue
				}
				hk := model.Hook{Event: event, Matcher: matcher, Command: redact.Text(cmd), Project: project, Ref: d.ref(cmd)}
				if event == "PreToolUse" && matcherCoversBash(matcher) {
					if g := hookGuard(e, cmd); g != "" {
						hk.Guards = g
						a.Mitigations = append(a.Mitigations, model.Mitigation{Covers: "out-bash", Project: project, Ref: hk.Ref,
							Detail: e.T("el hook %s %s", filepath.Base(first(hookTarget(e, cmd), strings.Fields(cmd)[0])), g)})
					}
				}
				if issue := hookIssue(e, cmd); issue != "" {
					hk.Issue = issue
					a.Flag("HK-001", event+" → "+hk.Command+" ("+issue+")",
						e.T("Mueve el script a una carpeta tuya (por ejemplo ~/.claude/hooks/) con permisos 700."), hk.Ref)
				}
				a.Hooks = append(a.Hooks, hk)
			}
		}
	}
}

// hookTarget returns the script a hook command runs, or "" when it cannot tell.
func hookTarget(e *Env, cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	target := fields[0]
	switch filepath.Base(target) {
	case "bash", "sh", "zsh", "python", "python3", "node", "bun", "deno", "ruby", "perl":
		target = ""
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "-") {
				target = f
				break
			}
		}
	}
	target = strings.Trim(e.expand(target), `"'`)
	if target == "" || strings.Contains(target, "$") || !filepath.IsAbs(target) {
		return ""
	}
	return target
}

// hookIssue explains why a hook command could be tampered with, or returns "".
func hookIssue(e *Env, cmd string) string {
	target := hookTarget(e, cmd)
	if target == "" {
		return ""
	}
	for _, tmp := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(target, tmp) {
			return e.T("está en un directorio temporal compartido")
		}
	}
	if fi, err := os.Stat(target); err == nil && fi.Mode().Perm()&0o002 != 0 {
		return e.T("cualquier usuario puede modificarlo")
	}
	if fi, err := os.Stat(filepath.Dir(target)); err == nil && fi.Mode().Perm()&0o002 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return e.T("su carpeta es escribible por cualquier usuario")
	}
	return ""
}

func unique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
