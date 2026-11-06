// Command squadwatch audits the AI agents on this machine: what is installed,
// what each one can do, what it exposes and how risky it is.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/detect"
	"github.com/sergio-lopez-dev/squadwatch/internal/diff"
	"github.com/sergio-lopez-dev/squadwatch/internal/i18n"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/report"
	"github.com/sergio-lopez-dev/squadwatch/internal/scan"
	"github.com/sergio-lopez-dev/squadwatch/internal/server"
	"github.com/sergio-lopez-dev/squadwatch/internal/store"
)

const usageES = `Squadwatch %s · auditor de seguridad para agentes de IA

Uso:
  squadwatch scan       Inventario y riesgos (guarda el escaneo para comparar)
  squadwatch agents     Lista los agentes detectados
  squadwatch show ID    Detalle de un agente: permisos, MCP, hooks, trifecta
  squadwatch mcp        Servidores MCP de todos los agentes
  squadwatch findings   Hallazgos con su evidencia y cómo corregirlos
  squadwatch trifecta   Qué agentes juntan datos, contenido no fiable y salida
  squadwatch paths      Caminos de ataque
  squadwatch diff       Qué ha cambiado desde el último escaneo guardado
  squadwatch history    Evolución del riesgo
  squadwatch serve      Dashboard en http://127.0.0.1:7777
  squadwatch rules      Reglas que comprueba
  squadwatch version

Todo funciona sin red y sin ejecutar código de terceros. Los secretos se
muestran siempre enmascarados. Añade -h a cualquier comando para ver sus opciones;
-lang en|es elige el idioma (por defecto, SQUADWATCH_LANG o el del sistema).
`

const usageEN = `Squadwatch %s · security auditor for AI agents

Usage:
  squadwatch scan       Inventory and risks (saves the scan for comparisons)
  squadwatch agents     List the agents found
  squadwatch show ID    Detail of one agent: permissions, MCP, hooks, trifecta
  squadwatch mcp        MCP servers of every agent
  squadwatch findings   Findings with their evidence and how to fix them
  squadwatch trifecta   Which agents combine data, untrusted content and a way out
  squadwatch paths      Attack paths
  squadwatch diff       What changed since the last saved scan
  squadwatch history    Risk over time
  squadwatch serve      Dashboard at http://127.0.0.1:7777
  squadwatch rules      Rules it checks
  squadwatch version

Everything works offline and without running third-party code. Secrets are
always masked. Add -h to any command to see its options; -lang en|es picks
the language (default: SQUADWATCH_LANG or the system locale).
`

// lang is the language of the whole run: -lang, else SQUADWATCH_LANG or the locale.
var lang = i18n.FromEnv()

// T translates a message into the run's language.
func T(msg string, args ...any) string { return lang.T(msg, args...) }

func usage() string {
	if lang == i18n.ES {
		return usageES
	}
	return usageEN
}

// langFromArgs reads -lang before the command's own flags are parsed, so
// that every message, including flag errors, comes out in that language.
func langFromArgs(args []string) {
	for i, a := range args {
		v := ""
		switch {
		case a == "-lang" || a == "--lang":
			if i+1 < len(args) {
				v = args[i+1]
			}
		case strings.HasPrefix(a, "-lang=") || strings.HasPrefix(a, "--lang="):
			v = a[strings.Index(a, "=")+1:]
		}
		if l, ok := i18n.Parse(v); ok {
			lang = l
		}
	}
	report.Lang = lang
}

func main() {
	langFromArgs(os.Args[1:])
	argv := os.Args[1:]
	// A global -lang before the command ("squadwatch -lang en scan") is not a command.
	for len(argv) > 0 && (strings.HasPrefix(argv[0], "-lang") || strings.HasPrefix(argv[0], "--lang")) {
		if strings.Contains(argv[0], "=") || len(argv) == 1 {
			argv = argv[1:]
		} else {
			argv = argv[2:]
		}
	}
	if len(argv) == 0 {
		fmt.Printf(usage(), scan.Version)
		return
	}
	cmd, args := argv[0], argv[1:]
	var err error
	switch cmd {
	case "scan":
		err = cmdScan(args)
	case "agents":
		err = cmdAgents(args)
	case "show":
		err = cmdShow(args)
	case "mcp":
		err = cmdMCP(args)
	case "findings":
		err = cmdFindings(args)
	case "trifecta":
		err = simple(args, "trifecta", report.Trifecta)
	case "paths":
		err = simple(args, "paths", report.Paths)
	case "diff":
		err = cmdDiff(args)
	case "history":
		err = cmdHistory(args)
	case "serve":
		err = cmdServe(args)
	case "rules":
		cmdRules()
	case "version", "-v", "--version":
		fmt.Println("squadwatch", scan.Version)
	case "help", "-h", "--help":
		fmt.Printf(usage(), scan.Version)
	default:
		fmt.Fprintf(os.Stderr, T("Comando desconocido: %s\n\n"), cmd)
		fmt.Fprintf(os.Stderr, usage(), scan.Version)
		os.Exit(2)
	}
	if err != nil {
		var ex exitErr
		if errors.As(err, &ex) {
			os.Exit(int(ex))
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit %d", int(e)) }

// common flags shared by every command.
type common struct {
	home string
	json bool
}

func newFlags(name string, c *common, withJSON bool) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	h, _ := os.UserHomeDir()
	fs.StringVar(&c.home, "home", h, T("directorio home que se audita"))
	fs.String("lang", string(lang), T("idioma: en o es (por defecto, el del sistema)"))
	if withJSON {
		fs.BoolVar(&c.json, "json", false, T("salida en JSON"))
	}
	return fs
}

func run(c common) *model.Scan {
	return runIn(c, lang)
}

func runIn(c common, l i18n.Lang) *model.Scan {
	e := detect.NewEnv(c.home)
	e.Lang = l
	return scan.Run(e)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func cmdScan(args []string) error {
	var c common
	fs := newFlags("scan", &c, false)
	format := fs.String("format", "table", T("table, json o md"))
	out := fs.String("o", "", T("escribe el informe en este fichero"))
	noSave := fs.Bool("no-save", false, T("no guarda el escaneo en el historial"))
	failOn := fs.String("fail-on", "", T("sale con código 1 si hay hallazgos de esta severidad o peor (crit, high, med)"))
	_ = fs.Parse(args)

	s := run(c)
	if !*noSave {
		if _, err := store.Save(s); err != nil {
			fmt.Fprintln(os.Stderr, T("Aviso: no se pudo guardar el escaneo:"), err)
		}
	}
	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
		report.Color = false
	}
	switch *format {
	case "json":
		if err := writeJSON(w, s); err != nil {
			return err
		}
	case "md", "markdown":
		report.Markdown(w, s)
	default:
		report.Summary(w, s)
	}
	if *out != "" {
		fmt.Printf(T("Informe guardado en %s\n"), *out)
	}
	return failIf(s, *failOn)
}

func failIf(s *model.Scan, level string) error {
	if level == "" {
		return nil
	}
	min, ok := model.ParseSeverity(level)
	if !ok {
		return fmt.Errorf(T("severidad desconocida: %s"), level)
	}
	for _, f := range s.Findings {
		if f.Sev.Rank() >= min.Rank() {
			return exitErr(1)
		}
	}
	return nil
}

func cmdAgents(args []string) error {
	var c common
	_ = newFlags("agents", &c, true).Parse(args)
	s := run(c)
	if c.json {
		return writeJSON(os.Stdout, s.Agents)
	}
	report.Agents(os.Stdout, s)
	return nil
}

func cmdShow(args []string) error {
	var c common
	fs := newFlags("show", &c, true)
	_ = fs.Parse(reorder(args))
	if fs.NArg() != 1 {
		return errors.New(T("indica un agente: squadwatch show claude-code (los ids salen en squadwatch agents)"))
	}
	s := run(c)
	a := s.Agent(fs.Arg(0))
	if a == nil {
		var ids []string
		for _, x := range s.Agents {
			ids = append(ids, x.ID)
		}
		return fmt.Errorf(T("no hay ningún agente %q. Detectados: %s"), fs.Arg(0), strings.Join(ids, ", "))
	}
	if c.json {
		return writeJSON(os.Stdout, struct {
			Agent    *model.Agent    `json:"agent"`
			Findings []model.Finding `json:"findings"`
		}{a, s.FindingsFor(a.ID)})
	}
	report.Show(os.Stdout, s, a)
	return nil
}

func cmdMCP(args []string) error {
	var c common
	_ = newFlags("mcp", &c, true).Parse(args)
	s := run(c)
	if c.json {
		type row struct {
			Agent string `json:"agent"`
			model.MCPServer
		}
		var rows []row
		for _, a := range s.Agents {
			for _, m := range a.MCP {
				rows = append(rows, row{a.ID, m})
			}
		}
		return writeJSON(os.Stdout, rows)
	}
	report.MCP(os.Stdout, s)
	return nil
}

func cmdFindings(args []string) error {
	var c common
	fs := newFlags("findings", &c, true)
	min := fs.String("min", "low", T("severidad mínima: crit, high, med, low"))
	agent := fs.String("agent", "", T("solo este agente"))
	short := fs.Bool("short", false, T("sin evidencia ni explicación"))
	failOn := fs.String("fail-on", "", T("sale con código 1 si hay hallazgos de esta severidad o peor"))
	_ = fs.Parse(reorder(args))
	sev, ok := model.ParseSeverity(*min)
	if !ok {
		return fmt.Errorf(T("severidad desconocida: %s"), *min)
	}
	s := run(c)
	var out []model.Finding
	for _, f := range s.Findings {
		if f.Sev.Rank() < sev.Rank() || (*agent != "" && f.Agent != *agent) {
			continue
		}
		if fs.NArg() > 0 && !strings.EqualFold(fs.Arg(0), f.ID) {
			continue
		}
		out = append(out, f)
	}
	if c.json {
		if out == nil {
			out = []model.Finding{}
		}
		if err := writeJSON(os.Stdout, out); err != nil {
			return err
		}
	} else {
		report.Findings(os.Stdout, s, out, !*short)
	}
	return failIf(&model.Scan{Findings: out}, *failOn)
}

func simple(args []string, name string, print func(io.Writer, *model.Scan)) error {
	var c common
	_ = newFlags(name, &c, true).Parse(args)
	s := run(c)
	if c.json {
		if name == "paths" {
			return writeJSON(os.Stdout, s.Paths)
		}
		type row struct {
			Agent    string         `json:"agent"`
			Trifecta model.Trifecta `json:"trifecta"`
		}
		var rows []row
		for _, a := range s.Agents {
			if !a.ModelHost {
				rows = append(rows, row{a.ID, a.Trifecta})
			}
		}
		return writeJSON(os.Stdout, rows)
	}
	print(os.Stdout, s)
	return nil
}

func cmdDiff(args []string) error {
	var c common
	_ = newFlags("diff", &c, true).Parse(args)
	old, err := store.Latest()
	if errors.Is(err, store.ErrNone) {
		return errors.New(T("todavía no hay escaneos guardados: ejecuta squadwatch scan primero"))
	}
	if err != nil {
		return err
	}
	cur := run(c)
	changes := diff.Compare(old, cur, lang)
	if c.json {
		if changes == nil {
			changes = []diff.Change{}
		}
		return writeJSON(os.Stdout, changes)
	}
	report.Diff(os.Stdout, old, cur, changes)
	return nil
}

func cmdHistory(args []string) error {
	var c common
	_ = newFlags("history", &c, true).Parse(args)
	h := store.History()
	if c.json {
		if h == nil {
			h = []store.Point{}
		}
		return writeJSON(os.Stdout, h)
	}
	if len(h) == 0 {
		fmt.Println(T("Todavía no hay escaneos guardados: ejecuta squadwatch scan."))
		return nil
	}
	rows := [][]string{{T("fecha"), T("riesgo"), "", T("agentes"), T("hallazgos"), T("críticos")}}
	for _, p := range h {
		rows = append(rows, []string{p.Time[:16], report.Risk(p.Risk), report.Meter(p.Risk), fmt.Sprint(p.Agents), fmt.Sprint(p.Findings), fmt.Sprint(p.Crit)})
	}
	report.Table(os.Stdout, rows)
	fmt.Printf("\n%s\n", report.Dim(T("Guardados en %s", store.Dir())))
	return nil
}

func cmdServe(args []string) error {
	var c common
	fs := newFlags("serve", &c, false)
	addr := fs.String("addr", "127.0.0.1:7777", T("dirección de escucha (solo se admite localhost)"))
	_ = fs.Parse(args)
	return server.Serve(*addr, lang, func(l i18n.Lang) *model.Scan { return runIn(c, l) })
}

func cmdRules() {
	rows := [][]string{{"id", T("severidad"), T("regla")}}
	for _, r := range rulesCatalog() {
		rows = append(rows, []string{r[0], r[1], r[2]})
	}
	report.Table(os.Stdout, rows)
}

// reorder moves flags in front of positional arguments so that
// "show claude-code -json" works like "show -json claude-code".
func reorder(args []string) []string {
	withValue := map[string]bool{"lang": true, "agent": true, "min": true, "fail-on": true, "home": true, "format": true, "o": true, "addr": true}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if !strings.Contains(name, "=") && withValue[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, pos...)
}
