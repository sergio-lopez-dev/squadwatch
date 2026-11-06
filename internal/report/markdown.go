package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

// Markdown writes a shareable report.
func Markdown(w io.Writer, s *model.Scan) {
	fmt.Fprintf(w, T("# Informe de Squadwatch\n\n"))
	fmt.Fprintf(w, T("Equipo `%s` · %s · Squadwatch %s\n\n"), s.Host, s.Time.Local().Format("02/01/2006 15:04"), s.Version)
	fmt.Fprintf(w, T("**Riesgo del equipo: %d/100 (%s).** %d agentes, %d servidores MCP, %d hallazgos (%d críticos, %d altos, %d medios).\n\n"),
		s.Risk, RiskWord(s.Risk), len(s.Agents), s.MCPCount(), len(s.Findings), s.Count(model.Crit), s.Count(model.High), s.Count(model.Med))
	fmt.Fprintf(w, T("## Agentes\n\n| Agente | Versión | Modo | MCP | Riesgo | Trifecta |\n|---|---|---|---|---|---|\n"))
	for _, a := range s.Agents {
		tri := "–"
		if !a.ModelHost {
			tri = map[bool]string{true: T("**cumple**"), false: countYes(a.Trifecta) + T(" de 3")}[a.Trifecta.Complete]
		}
		fmt.Fprintf(w, "| %s | %s | %s | %d | %d | %s |\n", a.Name, orDash(a.Version), md(orDash(a.Mode)), len(a.MCP), a.Risk, tri)
	}
	fmt.Fprintf(w, T("\n## Hallazgos\n\n"))
	if len(s.Findings) == 0 {
		fmt.Fprintf(w, T("Ninguno.\n"))
	}
	for _, f := range s.Findings {
		fmt.Fprintf(w, "### %s · %s · %s\n\n**%s.** %s\n\n", T(f.Sev.Label()), f.ID, agentName(s, f.Agent), f.Title, f.Why)
		for _, e := range f.Evidence {
			l := loc(model.Ref{File: e.File, Line: e.Line})
			if l != "" {
				l = "`" + l + "` "
			}
			fmt.Fprintf(w, "- %s%s\n", l, md(e.Text))
		}
		fmt.Fprintf(w, T("\n**Qué hacer:** %s\n\n"), f.Fix)
		if len(f.Refs) > 0 {
			fmt.Fprintf(w, "_%s_\n\n", strings.Join(f.Refs, " · "))
		}
	}
}

func md(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
