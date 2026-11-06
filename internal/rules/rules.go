// Package rules turns what the detectors saw into findings.
package rules

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/i18n"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/redact"
)

// Rule is the fixed text of one check.
type Rule struct {
	ID    string
	Sev   model.Severity
	Title string
	Why   string
	Fix   string
	Refs  []string
}

const (
	llm01 = "OWASP LLM01 Prompt Injection"
	llm02 = "OWASP LLM02 Sensitive Information Disclosure"
	llm03 = "OWASP LLM03 Supply Chain"
	llm06 = "OWASP LLM06 Excessive Agency"
	llm10 = "OWASP LLM10 Unbounded Consumption"
)

// Catalog lists every rule Squadwatch can report.
var Catalog = []Rule{
	{"TRI-001", model.Crit, "Cumple la trifecta letal",
		"Junta acceso a datos privados, contacto con contenido no fiable y una vía para sacar datos sin pedir confirmación. Una instrucción escondida en una web, un issue o un fichero puede hacer que el agente lea tus datos y los envíe fuera.",
		"Rompe uno de los tres lados. Lo más fácil suele ser que la salida (shell de red, servidores MCP que publican) pida confirmación.", []string{llm01, llm06}},
	{"AGT-001", model.Crit, "Ejecuta acciones sin pedir confirmación",
		"Cualquier acción que proponga el agente se ejecuta sin que la veas, incluidas las que vengan de una inyección de prompt.",
		"Desactiva el modo sin confirmación.", []string{llm06}},
	{"AGT-002", model.High, "Shell o red permitidas sin confirmación",
		"El agente puede ejecutar comandos o enviar datos a internet sin preguntarte.",
		"Mueve esas reglas de allow a ask.", []string{llm06}},
	{"AGT-003", model.Med, "Nunca pide aprobación",
		"La sandbox limita el daño, pero el agente modifica ficheros y ejecuta comandos sin confirmación.",
		"Usa approval_policy = \"on-request\".", []string{llm06}},
	{"AGT-004", model.High, "Sandbox desactivada por completo",
		"Los comandos del agente tienen acceso total al disco y a la red.",
		"Usa sandbox_mode = \"workspace-write\".", []string{llm06}},
	{"SEC-001", model.High, "Acceso a todo tu HOME o al disco",
		"El agente puede leer ~/.ssh, ~/.aws, ficheros .env y la configuración de otros agentes.",
		"Limita los directorios adicionales a los que necesites.", []string{llm02, llm06}},
	{"MCP-001", model.High, "Secreto en texto plano en la configuración MCP",
		"Cualquier programa que lea tu HOME, incluidos otros agentes, puede leer la credencial.",
		"Muévela a una variable de entorno o al llavero del sistema, y rótala porque ya estuvo expuesta.", []string{llm02}},
	{"MCP-002", model.Med, "Servidor MCP sin versión fijada",
		"Cada arranque descarga la última versión publicada. Si el paquete se compromete, ejecutas el código nuevo sin saberlo.",
		"Fija una versión exacta (paquete@1.2.3, paquete==1.2.3) o una imagen por digest.", []string{llm03}},
	{"MCP-003", model.High, "Servidor MCP remoto sin cifrar",
		"El tráfico con el servidor, incluidas las credenciales, viaja en claro por la red.",
		"Usa la URL https:// del servidor.", []string{llm02}},
	{"MCP-006", model.High, "Servidor de ficheros con acceso a todo el HOME o al disco",
		"Incluye ~/.ssh, ~/.config y los .env de todos tus proyectos.",
		"Limita la raíz del servidor a las carpetas que necesites.", []string{llm06}},
	{"MCP-007", model.Med, "Aprueba automáticamente los servidores MCP de cualquier proyecto",
		"Un repositorio clonado puede traer su propio .mcp.json y el agente lo arrancará sin preguntarte.",
		"Aprueba los servidores de cada proyecto uno a uno.", []string{llm03}},
	{"HK-001", model.High, "Un hook ejecuta un script que otros pueden modificar",
		"Quien cambie ese script ejecutará código cada vez que el agente dispare el hook.",
		"Mueve el script a una carpeta tuya con permisos 700.", []string{llm03}},
	{"INS-001", model.High, "Fichero de instrucciones con texto invisible",
		"Tú no ves esos caracteres, pero el modelo sí los lee. Es una técnica conocida para colar instrucciones.",
		"Revisa el fichero, elimina los caracteres invisibles y averigua de dónde vino.", []string{llm01}},
	{"NET-001", model.High, "Servidor de modelos abierto a la red sin autenticación",
		"Cualquier equipo de tu red, o de una wifi pública, puede usar tus modelos, descargar otros o borrarlos.",
		"Haz que escuche solo en 127.0.0.1.", []string{llm10}},
}

var byID = func() map[string]Rule {
	m := map[string]Rule{}
	for _, r := range Catalog {
		m[r.ID] = r
	}
	return m
}()

// Lookup returns a rule by id.
func Lookup(id string) (Rule, bool) {
	r, ok := byID[id]
	return r, ok
}

type collector struct {
	byKey map[string]*model.Finding
	order []string
	home  string
	lang  i18n.Lang
}

func (c *collector) add(rule string, a *model.Agent, ev model.Evidence, fix string, sev model.Severity) {
	r := byID[rule]
	if sev == "" {
		sev = r.Sev
	}
	key := strings.ToLower(rule) + ":" + a.ID
	f, ok := c.byKey[key]
	if !ok {
		f = &model.Finding{Key: key, ID: r.ID, Sev: sev, Agent: a.ID, Title: c.lang.T(r.Title), Why: c.lang.T(r.Why), Fix: c.lang.T(r.Fix), Refs: r.Refs}
		c.byKey[key] = f
		c.order = append(c.order, key)
	} else if sev.Rank() > f.Sev.Rank() {
		f.Sev = sev
	}
	if fix != "" {
		f.Fix = fix
	}
	ev.Text = redact.Text(ev.Text)
	if c.home != "" {
		// Keep Claude Code's absolute form //home/user intact.
		ev.Text = strings.ReplaceAll(ev.Text, "/"+c.home, "\x00")
		ev.Text = strings.ReplaceAll(ev.Text, c.home, "~")
		ev.Text = strings.ReplaceAll(ev.Text, "\x00", "/"+c.home)
	}
	for _, x := range f.Evidence {
		if x == ev {
			return
		}
	}
	f.Evidence = append(f.Evidence, ev)
}

// Evaluate returns the findings for all agents, worst first. Agents must
// already have their trifecta computed.
func Evaluate(agents []model.Agent, home string, lang i18n.Lang) []model.Finding {
	c := &collector{byKey: map[string]*model.Finding{}, home: home, lang: lang}
	for i := range agents {
		a := &agents[i]
		for _, s := range a.Signals {
			c.add(s.Rule, a, model.Evidence{File: s.File, Line: s.Line, Text: s.Detail}, s.Fix, s.Sev)
		}
		for _, s := range a.MCP {
			mcpRules(c, a, s, home)
		}
		for _, f := range a.Instr {
			if f.Hidden > 0 {
				text := c.lang.T("%d caracteres invisibles", f.Hidden)
				if f.Decoded != "" {
					text += c.lang.T(" · dicen: %q", truncate(f.Decoded, 120))
				}
				c.add("INS-001", a, model.Evidence{File: f.Path, Line: f.Line, Text: text}, "", "")
			}
		}
		scopes := a.Scopes
		if len(scopes) == 0 {
			scopes = []model.ScopeTrifecta{{Project: a.Trifecta.Scope, Trifecta: a.Trifecta}}
		}
		var where []string
		for _, st := range scopes {
			t := st.Trifecta
			if !t.Complete {
				continue
			}
			label := c.lang.T("En cualquier proyecto")
			if st.Project != "" {
				label = c.lang.T("En %s", st.Project)
				where = append(where, st.Project)
			}
			c.add("TRI-001", a, model.Evidence{Text: label + c.lang.T(" · datos privados: %s", strings.Join(t.PrivWhy, ", "))}, "", "")
			c.add("TRI-001", a, model.Evidence{Text: label + c.lang.T(" · contenido no fiable: %s", strings.Join(t.UntrWhy, ", "))}, "", "")
			c.add("TRI-001", a, model.Evidence{Text: label + c.lang.T(" · salida sin confirmación: %s", strings.Join(t.OutWhy, ", "))}, "", "")
		}
		if len(where) > 0 {
			those := c.lang.T("ese proyecto")
			if len(where) > 1 {
				those = c.lang.T("esos proyectos")
			}
			c.byKey["tri-001:"+a.ID].Fix = c.lang.T("Rompe uno de los tres lados en %s. Lo más fácil suele ser que la salida pida confirmación: quita de allow las reglas con comodín de %s.", strings.Join(where, c.lang.T(" y ")), those)
		}
	}
	out := make([]model.Finding, 0, len(c.order))
	for _, k := range c.order {
		out = append(out, *c.byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Sev.Rank() != out[j].Sev.Rank() {
			return out[i].Sev.Rank() > out[j].Sev.Rank()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func mcpRules(c *collector, a *model.Agent, s model.MCPServer, home string) {
	if s.Disabled {
		return
	}
	for _, sec := range s.Secrets {
		c.add("MCP-001", a, model.Evidence{File: s.File, Line: first(sec.Line, s.Line),
			Text: fmt.Sprintf("%s → %s (%s) = %s", s.Name, sec.Key, sec.Where, sec.Masked)}, "", "")
	}
	if !s.Pinned {
		c.add("MCP-002", a, model.Evidence{File: s.File, Line: s.Line,
			Text: fmt.Sprintf("%s: %s %s (%s)", s.Name, s.Command, strings.Join(s.Args, " "), s.Pin)}, "", "")
	}
	if strings.HasPrefix(s.URL, "http://") && !strings.Contains(s.URL, "://localhost") && !strings.Contains(s.URL, "://127.0.0.1") {
		c.add("MCP-003", a, model.Evidence{File: s.File, Line: s.Line, Text: s.Name + ": " + s.URL}, "", "")
	}
	if s.Kind == "filesystem" {
		for _, arg := range s.Args {
			p := filepath.Clean(strings.Replace(arg, "~", home, 1))
			if p == "/" || p == home {
				c.add("MCP-006", a, model.Evidence{File: s.File, Line: s.Line, Text: c.lang.T("%s: raíz %s", s.Name, arg)},
					c.lang.T("Cambia la raíz %s por las carpetas concretas que necesites.", arg), "")
			}
		}
	}
}

func first(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
