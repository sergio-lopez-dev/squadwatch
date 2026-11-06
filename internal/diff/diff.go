// Package diff compares two scans.
package diff

import (
	"fmt"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

// Change is one difference between two scans.
type Change struct {
	Kind  string         `json:"kind"` // add, del, mod
	Area  string         `json:"area"` // agente, mcp, hallazgo, permiso, riesgo
	Agent string         `json:"agent,omitempty"`
	Text  string         `json:"text"`
	Sev   model.Severity `json:"sev,omitempty"`
}

// Compare lists what changed from old to cur.
func Compare(old, cur *model.Scan) []Change {
	var out []Change
	oldA := index(old)
	curA := index(cur)
	for id, a := range curA {
		if _, ok := oldA[id]; !ok {
			out = append(out, Change{Kind: "add", Area: "agente", Agent: id, Text: "Nuevo agente: " + a.Name})
		}
	}
	for id, a := range oldA {
		if _, ok := curA[id]; !ok {
			out = append(out, Change{Kind: "del", Area: "agente", Agent: id, Text: "Ya no está: " + a.Name})
		}
	}
	for id, a := range curA {
		b, ok := oldA[id]
		if !ok {
			continue
		}
		om := servers(b)
		for k, s := range servers(a) {
			o, ok := om[k]
			switch {
			case !ok:
				out = append(out, Change{Kind: "add", Area: "mcp", Agent: id, Text: fmt.Sprintf("%s: nuevo servidor MCP %s (%s)", a.Name, s.Name, s.Scope)})
			case cmdline(o) != cmdline(s):
				out = append(out, Change{Kind: "mod", Area: "mcp", Agent: id, Text: fmt.Sprintf("%s: %s cambió de «%s» a «%s»", a.Name, s.Name, cmdline(o), cmdline(s))})
			}
		}
		cm := servers(a)
		for k, s := range om {
			if _, ok := cm[k]; !ok {
				out = append(out, Change{Kind: "del", Area: "mcp", Agent: id, Text: fmt.Sprintf("%s: se quitó el servidor MCP %s", a.Name, s.Name)})
			}
		}
		if a.Mode != b.Mode {
			out = append(out, Change{Kind: "mod", Area: "permiso", Agent: id, Text: fmt.Sprintf("%s: modo «%s» → «%s»", a.Name, b.Mode, a.Mode)})
		}
		op := perms(b)
		for k := range perms(a) {
			if !op[k] {
				out = append(out, Change{Kind: "add", Area: "permiso", Agent: id, Text: fmt.Sprintf("%s: nueva regla %s", a.Name, k)})
			}
		}
		if a.Trifecta.Complete != b.Trifecta.Complete {
			t := "ya no cumple la trifecta"
			if a.Trifecta.Complete {
				t = "ahora cumple la trifecta"
			}
			out = append(out, Change{Kind: "mod", Area: "riesgo", Agent: id, Text: a.Name + ": " + t, Sev: model.Crit})
		}
	}
	oldF := map[string]model.Finding{}
	for _, f := range old.Findings {
		oldF[f.Key] = f
	}
	curF := map[string]bool{}
	for _, f := range cur.Findings {
		curF[f.Key] = true
		if _, ok := oldF[f.Key]; !ok {
			out = append(out, Change{Kind: "add", Area: "hallazgo", Agent: f.Agent, Sev: f.Sev, Text: f.ID + " " + f.Title})
		}
	}
	for k, f := range oldF {
		if !curF[k] {
			out = append(out, Change{Kind: "del", Area: "hallazgo", Agent: f.Agent, Sev: f.Sev, Text: f.ID + " resuelto: " + f.Title})
		}
	}
	if old.Risk != cur.Risk {
		out = append(out, Change{Kind: "mod", Area: "riesgo", Text: fmt.Sprintf("Riesgo del equipo %d → %d", old.Risk, cur.Risk)})
	}
	return out
}

func index(s *model.Scan) map[string]model.Agent {
	m := map[string]model.Agent{}
	for _, a := range s.Agents {
		m[a.ID] = a
	}
	return m
}

func servers(a model.Agent) map[string]model.MCPServer {
	m := map[string]model.MCPServer{}
	for _, s := range a.MCP {
		m[s.Scope+"|"+s.Name] = s
	}
	return m
}

func perms(a model.Agent) map[string]bool {
	m := map[string]bool{}
	for _, p := range a.Perms {
		m[p.Kind+" "+p.Rule] = true
	}
	return m
}

func cmdline(s model.MCPServer) string {
	if s.URL != "" {
		return s.URL
	}
	return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
}
