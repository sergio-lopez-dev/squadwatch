// Package report prints scans for people: terminal tables and Markdown.
package report

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sergio-lopez-dev/squadwatch/internal/diff"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

// Color decides whether to print ANSI colors.
var Color = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string { return paint("1", s) }
func Dim(s string) string  { return paint("2", s) }
func Red(s string) string  { return paint("31", s) }
func Ora(s string) string  { return paint("38;5;208", s) }
func Yel(s string) string  { return paint("33", s) }
func Grn(s string) string  { return paint("32", s) }
func Acc(s string) string  { return paint("36", s) }

// Sev prints a severity as a colored label.
func Sev(s model.Severity) string {
	l := strings.ToUpper(s.Label())
	l += strings.Repeat(" ", 7-utf8.RuneCountInString(l))
	switch s {
	case model.Crit:
		return paint("1;97;41", " "+l+" ")
	case model.High:
		return paint("1;30;48;5;208", " "+l+" ")
	case model.Med:
		return paint("1;30;43", " "+l+" ")
	}
	return paint("30;47", " "+l+" ")
}

// Risk colors a 0–100 score.
func Risk(r int) string {
	s := fmt.Sprint(r)
	switch {
	case r >= 70:
		return Red(s)
	case r >= 50:
		return Ora(s)
	case r >= 30:
		return Yel(s)
	}
	return Grn(s)
}

func RiskWord(r int) string {
	switch {
	case r >= 70:
		return "crítico"
	case r >= 50:
		return "alto"
	case r >= 30:
		return "medio"
	}
	return "bajo"
}

// Meter draws a 10-block bar.
func Meter(r int) string {
	n := (r + 5) / 10
	full := strings.Repeat("█", n)
	rest := strings.Repeat("░", 10-n)
	switch {
	case r >= 70:
		full = Red(full)
	case r >= 50:
		full = Ora(full)
	case r >= 30:
		full = Yel(full)
	default:
		full = Grn(full)
	}
	return full + Dim(rest)
}

func State(s model.State) string {
	switch s {
	case model.Yes:
		return Red("▲")
	case model.Partial:
		return Yel("△")
	}
	return Dim("·")
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func width(s string) int { return utf8.RuneCountInString(ansi.ReplaceAllString(s, "")) }

// Table prints rows with aligned columns. The first row is the header.
func Table(w io.Writer, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && width(c) > widths[i] {
				widths[i] = width(c)
			}
		}
	}
	for ri, r := range rows {
		var b strings.Builder
		b.WriteString(" ")
		for i, c := range r {
			if ri == 0 {
				c = Dim(strings.ToUpper(c))
			}
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-width(c)+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

func countLabel(fs []model.Finding) string {
	var parts []string
	for _, sev := range []model.Severity{model.Crit, model.High, model.Med, model.Low} {
		n := 0
		for _, f := range fs {
			if f.Sev == sev {
				n++
			}
		}
		if n == 0 {
			continue
		}
		label := fmt.Sprintf("%d %s", n, strings.ToLower(sev.Label()))
		if n > 1 {
			label += "s"
		}
		switch sev {
		case model.Crit:
			label = Red(label)
		case model.High:
			label = Ora(label)
		case model.Med:
			label = Yel(label)
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return Grn("sin hallazgos")
	}
	return strings.Join(parts, " · ")
}

func status(a model.Agent) string {
	switch {
	case len(a.Listeners) > 0 && a.Listeners[0].Public:
		return Ora("◆") + fmt.Sprintf(" %s:%d", a.Listeners[0].Addr, a.Listeners[0].Port)
	case a.Running && len(a.PIDs) > 0:
		return Grn("■") + fmt.Sprintf(" activo · pid %d", a.PIDs[0])
	case a.Running:
		return Grn("■") + " activo"
	}
	return "instalado"
}

// Summary prints the result of `squadwatch scan`.
func Summary(w io.Writer, s *model.Scan) {
	fmt.Fprintf(w, "%s %s · escaneo estático %s\n", Bold("Squadwatch"), s.Version, Dim("(no se ha ejecutado código de terceros)"))
	fmt.Fprintf(w, "%s %d agentes · %d servidores MCP · %d ficheros leídos · %d ms\n\n", Grn("✓"), len(s.Agents), s.MCPCount(), s.Configs, s.DurationMS)
	if len(s.Agents) == 0 {
		fmt.Fprintln(w, "No se ha encontrado ningún agente de IA.")
		return
	}
	rows := [][]string{{"agente", "estado", "riesgo", "", "mcp", "hallazgos"}}
	for _, a := range s.Agents {
		mcp := "–"
		if len(a.MCP) > 0 {
			mcp = fmt.Sprint(len(a.MCP))
		}
		rows = append(rows, []string{Bold(a.Name), status(a), Risk(a.Risk), Meter(a.Risk), mcp, countLabel(s.FindingsFor(a.ID))})
	}
	Table(w, rows)
	fmt.Fprintf(w, "\n Riesgo del equipo %s %s · %s\n\n", Bold(Risk(s.Risk)+"/100"), "("+RiskWord(s.Risk)+")", countLabel(s.Findings))
	shown := 0
	for _, f := range s.Findings {
		if f.Sev.Rank() < model.High.Rank() || shown >= 8 {
			continue
		}
		fmt.Fprintf(w, " %s %-8s %s: %s\n", Sev(f.Sev), f.ID, agentName(s, f.Agent), f.Title)
		shown++
	}
	if rest := len(s.Findings) - shown; rest > 0 {
		fmt.Fprintf(w, " %s squadwatch findings\n", Dim(fmt.Sprintf("+ %d más →", rest)))
	}
	fmt.Fprintf(w, "\n%s squadwatch show <agente>   %s squadwatch serve\n", Dim("→"), Dim("→"))
}

func agentName(s *model.Scan, id string) string {
	if a := s.Agent(id); a != nil {
		return a.Name
	}
	return id
}

// Agents prints `squadwatch agents`.
func Agents(w io.Writer, s *model.Scan) {
	rows := [][]string{{"id", "versión", "estado", "modo", "config"}}
	for _, a := range s.Agents {
		cfg := "–"
		if len(a.Configs) > 0 {
			cfg = a.Configs[0]
			if len(a.Configs) > 1 {
				cfg += Dim(fmt.Sprintf(" (+%d)", len(a.Configs)-1))
			}
		}
		rows = append(rows, []string{Bold(a.ID), orDash(a.Version), status(a), orDash(a.Mode), cfg})
	}
	Table(w, rows)
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func capList(cs []model.Cap) string {
	if len(cs) == 0 {
		return "desconocidas"
	}
	names := map[model.Cap]string{model.Priv: "privado", model.Untr: "no fiable", model.Out: "salida"}
	var p []string
	for _, c := range cs {
		p = append(p, names[c])
	}
	return strings.Join(p, ", ")
}

// Show prints the detail of one agent.
func Show(w io.Writer, s *model.Scan, a *model.Agent) {
	fmt.Fprintf(w, "%s %s · %s · %s · riesgo %s\n\n", Bold(strings.ToUpper(a.Name)), orDash(a.Version), a.Kind, status(*a), Risk(a.Risk))
	sec := func(t string) { fmt.Fprintf(w, "%s\n", Acc(t)) }
	sec("PERMISOS")
	fmt.Fprintf(w, "  modo        %s\n", orDash(a.Mode))
	if a.Sandbox != "" {
		fmt.Fprintf(w, "  sandbox     %s\n", a.Sandbox)
	}
	for _, kind := range []string{"allow", "ask", "deny"} {
		var rs []string
		for _, p := range a.Perms {
			if p.Kind == kind {
				rs = append(rs, p.Rule)
			}
		}
		if len(rs) > 0 {
			label := map[string]string{"allow": "permitido", "ask": "pregunta", "deny": "denegado"}[kind]
			fmt.Fprintf(w, "  %-11s %s\n", label, Dim(fmt.Sprintf("%d reglas", len(rs))))
			for i, r := range rs {
				if i == 12 {
					fmt.Fprintf(w, "              %s\n", Dim(fmt.Sprintf("+ %d más (squadwatch show %s -json)", len(rs)-12, a.ID)))
					break
				}
				fmt.Fprintf(w, "              %s\n", clip(r, 100))
			}
		}
	}
	for _, st := range a.Settings {
		fmt.Fprintf(w, "  %s = %s %s\n", st.Key, st.Value, Dim(loc(st.Ref)))
	}
	if len(a.MCP) > 0 {
		sec("\nSERVIDORES MCP")
		for _, m := range a.MCP {
			extra := ""
			if m.Disabled {
				extra = Dim(" (desactivado)")
			}
			if m.AutoApproved {
				extra += Ora(" sin confirmación")
			}
			fmt.Fprintf(w, "  %-16s %-6s %s %s%s\n", m.Name, m.Transport, Dim("["+capList(m.Caps)+"]"), Dim(m.Scope), extra)
		}
	}
	if len(a.Hooks) > 0 {
		sec("\nHOOKS")
		for _, h := range a.Hooks {
			issue := ""
			if h.Issue != "" {
				issue = Red(" (" + h.Issue + ")")
			}
			if h.Guards != "" {
				issue += Grn(" (" + h.Guards + ")")
			}
			fmt.Fprintf(w, "  %-16s → %s%s\n", h.Event, clip(h.Command, 90), issue)
		}
	}
	if len(a.Instr) > 0 {
		sec("\nINSTRUCCIONES")
		for _, f := range a.Instr {
			st := Grn("limpio")
			if f.Hidden > 0 {
				st = Red(fmt.Sprintf("%d caracteres invisibles", f.Hidden))
			}
			fmt.Fprintf(w, "  %s %s\n", f.Path, st)
		}
	}
	if len(a.Listeners) > 0 {
		sec("\nPUERTOS")
		for _, l := range a.Listeners {
			pub := Grn("solo local")
			if l.Public {
				pub = Red("accesible desde la red")
			}
			fmt.Fprintf(w, "  %s:%d %s\n", l.Addr, l.Port, pub)
		}
	}
	if len(a.Mitigations) > 0 {
		sec("\nMITIGACIONES")
		for _, m := range a.Mitigations {
			where := ""
			if m.Project != "" {
				where = Dim(" (" + m.Project + ")")
			}
			fmt.Fprintf(w, "  %s %s%s\n", Grn("✓"), m.Detail, where)
		}
	}
	if !a.ModelHost {
		scopes := a.Scopes
		if len(scopes) == 0 {
			scopes = []model.ScopeTrifecta{{Project: a.Trifecta.Scope, Trifecta: a.Trifecta}}
		}
		for _, st := range scopes {
			t := st.Trifecta
			title := "\nTRIFECTA"
			switch {
			case len(scopes) > 1 && st.Project == "":
				title += " · fuera de proyectos con reglas propias"
			case st.Project != "":
				title += " · " + st.Project
			}
			sec(title)
			fmt.Fprintf(w, "  %s datos privados      %s\n", State(t.Priv), Dim(clip(strings.Join(t.PrivWhy, ", "), 110)))
			fmt.Fprintf(w, "  %s contenido no fiable %s\n", State(t.Untr), Dim(clip(strings.Join(t.UntrWhy, ", "), 110)))
			fmt.Fprintf(w, "  %s salida              %s\n", State(t.Out), Dim(clip(strings.Join(t.OutWhy, ", "), 110)))
			if t.Complete {
				fmt.Fprintf(w, "  %s\n", Red("→ CUMPLE la trifecta letal"))
			}
		}
	}
	for _, x := range a.Extras {
		fmt.Fprintf(w, "\n%s", Dim("· "+x))
	}
	if len(a.Extras) > 0 {
		fmt.Fprintln(w)
	}
	fs := s.FindingsFor(a.ID)
	if len(fs) > 0 {
		fmt.Fprintln(w)
		for _, f := range fs {
			fmt.Fprintf(w, " %s %-8s %s\n", Sev(f.Sev), f.ID, f.Title)
		}
	}
	fmt.Fprintf(w, "\n%s\n", Dim("Configuración leída: "+strings.Join(a.Configs, ", ")))
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func loc(r model.Ref) string {
	if r.File == "" {
		return ""
	}
	if r.Line > 0 {
		return fmt.Sprintf("%s:%d", r.File, r.Line)
	}
	return r.File
}

// MCP prints `squadwatch mcp`.
func MCP(w io.Writer, s *model.Scan) {
	rows := [][]string{{"servidor", "agente", "tipo", "versión", "credenciales", "aporta"}}
	for _, a := range s.Agents {
		for _, m := range a.MCP {
			pin := m.Pin
			if !m.Pinned {
				pin = Ora(pin)
			}
			cred := "–"
			if len(m.Secrets) > 0 {
				cred = Red("TEXTO PLANO")
			} else if len(m.EnvKeys) > 0 {
				cred = "env"
			}
			name := m.Name
			if m.Disabled {
				name += Dim(" (off)")
			}
			rows = append(rows, []string{Bold(name), a.ID, m.Transport, pin, cred, capList(m.Caps)})
		}
	}
	if len(rows) == 1 {
		fmt.Fprintln(w, "No hay servidores MCP configurados.")
		return
	}
	Table(w, rows)
}

// Findings prints the list of findings with their evidence.
func Findings(w io.Writer, s *model.Scan, fs []model.Finding, detail bool) {
	if len(fs) == 0 {
		fmt.Fprintln(w, Grn("✓ Ningún hallazgo con estos filtros."))
		return
	}
	for _, f := range fs {
		fmt.Fprintf(w, " %s %-8s %-16s %s\n", Sev(f.Sev), f.ID, agentName(s, f.Agent), f.Title)
		if !detail {
			continue
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "     %s %s\n", Dim(loc(model.Ref{File: e.File, Line: e.Line})), e.Text)
		}
		fmt.Fprintf(w, "     %s %s\n", Acc("Por qué:"), f.Why)
		fmt.Fprintf(w, "     %s %s\n\n", Grn("Qué hacer:"), f.Fix)
	}
}

// Trifecta prints the matrix.
func Trifecta(w io.Writer, s *model.Scan) {
	rows := [][]string{{"agente", "datos priv.", "no fiable", "salida", "resultado"}}
	for _, a := range s.Agents {
		if a.ModelHost {
			continue
		}
		t := a.Trifecta
		res := countYes(t) + " de 3"
		if t.Complete {
			res = Red("CUMPLE")
		}
		if n := completeScopes(a); n > 1 {
			res += Dim(fmt.Sprintf(" en %d proyectos", n))
		} else if t.Scope != "" {
			res += Dim(" en " + t.Scope)
		}
		rows = append(rows, []string{Bold(a.Name), State(t.Priv), State(t.Untr), State(t.Out), res})
	}
	Table(w, rows)
	fmt.Fprintf(w, "\n%s\n", Dim("▲ sin confirmación   △ con confirmación   · no"))
}

func countYes(t model.Trifecta) string {
	n := 0
	for _, x := range []model.State{t.Priv, t.Untr, t.Out} {
		if x == model.Yes {
			n++
		}
	}
	return fmt.Sprint(n)
}

// Paths prints attack paths.
func Paths(w io.Writer, s *model.Scan) {
	if len(s.Paths) == 0 {
		fmt.Fprintln(w, Grn("✓ No hay caminos de ataque: ningún agente junta datos privados y contenido no fiable."))
		return
	}
	for _, p := range s.Paths {
		state := map[string]string{"open": Red("ABIERTO"), "partial": Yel("PARCIAL"), "cut": Grn("CORTADO")}[p.State]
		arrow := Dim(" → ")
		who := Bold(agentName(s, p.Agent))
		if p.Scope != "" {
			who += Dim(" en " + p.Scope)
		}
		fmt.Fprintf(w, " %-9s %s  %s%s%s%s%s%s%s\n", state, p.ID, p.Source, arrow, who, arrow, p.Data, arrow, clip(p.Sink, 70))
	}
}

// Diff prints changes between two scans.
func Diff(w io.Writer, old, cur *model.Scan, changes []diff.Change) {
	fmt.Fprintf(w, "Comparando con el escaneo del %s %s\n\n", old.Time.Local().Format("02/01/2006 15:04"), Dim(fmt.Sprintf("(riesgo %d → %d)", old.Risk, cur.Risk)))
	if len(changes) == 0 {
		fmt.Fprintln(w, Grn("✓ Sin cambios."))
		return
	}
	for _, c := range changes {
		mark := map[string]string{"add": Grn("+"), "del": Red("-"), "mod": Yel("~")}[c.Kind]
		fmt.Fprintf(w, " %s %-9s %s\n", mark, Dim(c.Area), c.Text)
	}
}

func completeScopes(a model.Agent) int {
	n := 0
	for _, st := range a.Scopes {
		if st.Trifecta.Complete {
			n++
		}
	}
	return n
}
