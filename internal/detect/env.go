// Package detect finds AI agents on the machine and reads their configuration.
//
// Detectors only read files, /proc and listening sockets. They never start an
// agent or an MCP server.
package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/i18n"
	"github.com/sergio-lopez-dev/squadwatch/internal/jsonc"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/sysinfo"
)

// Env is everything a detector may look at. Tests build one that points at a
// fake home directory.
type Env struct {
	Home      string
	GOOS      string
	Procs     []sysinfo.Proc
	Listeners []sysinfo.Listener
	LookPath  func(string) (string, error)
	// Lang is the language of every text the detectors write.
	Lang i18n.Lang
	// NoSystem limits detection to files under Home. Tests use it so the
	// real machine does not leak into a fake home.
	NoSystem bool
	read     map[string]bool
}

// allowed reports whether a path may be inspected.
func (e *Env) allowed(p string) bool {
	return !e.NoSystem || strings.HasPrefix(p, e.Home)
}

// NewEnv inspects the real machine.
func NewEnv(home string) *Env {
	return &Env{
		Home:      home,
		GOOS:      runtime.GOOS,
		Procs:     sysinfo.Processes(),
		Listeners: sysinfo.Listeners(),
		LookPath:  exec.LookPath,
		Lang:      i18n.FromEnv(),
		read:      map[string]bool{},
	}
}

// T translates a message into the scan's language.
func (e *Env) T(msg string, args ...any) string { return e.Lang.T(msg, args...) }

// N picks the singular or plural message in the scan's language.
func (e *Env) N(n int, one, many string) string { return e.Lang.N(n, one, many) }

// ConfigsRead is how many files the detectors opened.
func (e *Env) ConfigsRead() int { return len(e.read) }

func (e *Env) p(parts ...string) string {
	return filepath.Join(append([]string{e.Home}, parts...)...)
}

// expand resolves ~ and $HOME.
func (e *Env) expand(p string) string {
	switch {
	case p == "~":
		return e.Home
	case strings.HasPrefix(p, "~/"):
		return filepath.Join(e.Home, p[2:])
	}
	p = strings.ReplaceAll(p, "${HOME}", e.Home)
	return strings.ReplaceAll(p, "$HOME", e.Home)
}

// short shows a path relative to the home directory, as people write it.
func (e *Env) short(p string) string {
	if e.Home != "" && (p == e.Home || strings.HasPrefix(p, e.Home+string(os.PathSeparator))) {
		return "~" + strings.TrimPrefix(p, e.Home)
	}
	return p
}

// which finds a program in PATH or in the extra locations given.
func (e *Env) which(name string, extra ...string) string {
	if e.LookPath != nil {
		if p, err := e.LookPath(name); err == nil {
			return p
		}
	}
	for _, x := range extra {
		if e.allowed(x) && exists(x) {
			return x
		}
	}
	return ""
}

// running returns the pids of processes that match.
func (e *Env) running(match func(sysinfo.Proc) bool) []int {
	var pids []int
	for _, p := range e.Procs {
		if match(p) {
			pids = append(pids, p.PID)
		}
	}
	sort.Ints(pids)
	return pids
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// doc is a parsed config file that remembers its raw bytes for line lookups.
type doc struct {
	Path  string
	Short string
	Raw   []byte
	Data  map[string]any
}

// readJSON reads a JSON or JSONC file. An empty file is an empty object.
func (e *Env) readJSON(p string) (*doc, error) {
	if !e.allowed(p) {
		return nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	e.read[p] = true
	d := &doc{Path: p, Short: e.short(p), Raw: raw, Data: map[string]any{}}
	if len(bytes.TrimSpace(raw)) == 0 {
		return d, nil
	}
	if err := json.Unmarshal(jsonc.Strip(raw), &d.Data); err != nil {
		return d, fmt.Errorf("%s: %w", d.Short, err)
	}
	return d, nil
}

// line returns the 1-based line of the first needle found, or 0.
func (d *doc) line(needles ...string) int {
	if d == nil {
		return 0
	}
	for _, n := range needles {
		if n == "" {
			continue
		}
		if i := bytes.Index(d.Raw, []byte(n)); i >= 0 {
			return bytes.Count(d.Raw[:i], []byte{'\n'}) + 1
		}
	}
	return 0
}

func (d *doc) ref(needles ...string) model.Ref {
	if d == nil {
		return model.Ref{}
	}
	return model.Ref{File: d.Short, Line: d.line(needles...)}
}

// --- small helpers for map[string]any trees ---

func getMap(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func getStr(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func getBool(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

func getSlice(m map[string]any, k string) []any {
	v, _ := m[k].([]any)
	return v
}

func getStrSlice(m map[string]any, k string) []string {
	var out []string
	for _, v := range getSlice(m, k) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// walk calls fn for every key in a nested map, with its dotted path.
func walk(m map[string]any, prefix string, fn func(path string, v any)) {
	for _, k := range sortedKeys(m) {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		fn(p, m[k])
		if sub, ok := m[k].(map[string]any); ok {
			walk(sub, p, fn)
		}
	}
}

// truthy reports whether a setting value means "on".
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(t)
		return s == "true" || s == "on" || s == "yes" || s == "yolo" || s == "always"
	}
	return false
}
