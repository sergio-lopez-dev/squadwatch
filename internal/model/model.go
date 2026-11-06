// Package model holds the inventory types shared by every part of Squadwatch.
//
// Everything in these types is safe to print or store: secrets are masked
// before they reach the model.
package model

import "time"

// Severity of a finding.
type Severity string

const (
	Crit Severity = "crit"
	High Severity = "high"
	Med  Severity = "med"
	Low  Severity = "low"
	Info Severity = "info"
)

// Rank orders severities so that a higher number is worse.
func (s Severity) Rank() int {
	switch s {
	case Crit:
		return 4
	case High:
		return 3
	case Med:
		return 2
	case Low:
		return 1
	}
	return 0
}

// Label is the Spanish name shown to people.
func (s Severity) Label() string {
	switch s {
	case Crit:
		return "Crítico"
	case High:
		return "Alto"
	case Med:
		return "Medio"
	case Low:
		return "Bajo"
	}
	return "Info"
}

// ParseSeverity accepts English codes and Spanish names.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "crit", "critical", "critico", "crítico":
		return Crit, true
	case "high", "alto":
		return High, true
	case "med", "medium", "medio":
		return Med, true
	case "low", "bajo":
		return Low, true
	case "info":
		return Info, true
	}
	return "", false
}

// Cap is one of the three capabilities of the lethal trifecta.
type Cap string

const (
	Priv Cap = "priv" // access to private data
	Untr Cap = "untr" // exposure to untrusted content
	Out  Cap = "out"  // a way to send data out
)

// State says whether an agent has a capability.
type State string

const (
	Yes     State = "y" // has it, without asking
	Partial State = "p" // has it, but a person must confirm
	No      State = "n"
)

// Ref points at a file and line that backs a statement.
type Ref struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// Setting is a notable configuration value.
type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Ref
}

// Perm is one permission rule (allow, ask or deny).
type Perm struct {
	Rule    string `json:"rule"`
	Kind    string `json:"kind"`
	Project string `json:"project,omitempty"` // "" = applies everywhere
	Ref
}

// Secret is a credential found in plain text. Only the masked form is kept.
type Secret struct {
	Key    string `json:"key"`
	Masked string `json:"masked"`
	Where  string `json:"where"`
	Line   int    `json:"line,omitempty"`
}

// MCPServer is one Model Context Protocol server wired into an agent.
type MCPServer struct {
	Name         string   `json:"name"`
	Scope        string   `json:"scope"`
	Transport    string   `json:"transport"`
	Command      string   `json:"command,omitempty"`
	Args         []string `json:"args,omitempty"`
	URL          string   `json:"url,omitempty"`
	EnvKeys      []string `json:"envKeys,omitempty"`
	Secrets      []Secret `json:"secrets,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Caps         []Cap    `json:"caps"`
	Known        bool     `json:"known"`
	Pin          string   `json:"pin"`
	Pinned       bool     `json:"pinned"`
	Disabled     bool     `json:"disabled,omitempty"`
	AutoApproved bool     `json:"autoApproved,omitempty"`
	Project      string   `json:"project,omitempty"` // "" = available in every project
	Ref
}

// Hook is a command an agent runs on its own at some event.
type Hook struct {
	Event   string `json:"event"`
	Matcher string `json:"matcher,omitempty"`
	Command string `json:"command"`
	Issue   string `json:"issue,omitempty"`
	Guards  string `json:"guards,omitempty"` // what the hook checks, if Squadwatch could tell
	Project string `json:"project,omitempty"`
	Ref
}

// Grant is a capability the agent's configuration gives it without
// confirmation, such as an allow rule with a wildcard.
type Grant struct {
	Cap     Cap
	Kind    string // bash, mode, web, read
	Reason  string
	Project string
}

// Mitigation is something that reduces a risk: a guard hook, a sandbox, a
// deny rule.
type Mitigation struct {
	Covers  string `json:"covers"` // out-bash, read-secrets
	Detail  string `json:"detail"`
	Project string `json:"project,omitempty"`
	Ref
}

// ScopeTrifecta is the trifecta of an agent inside one project.
type ScopeTrifecta struct {
	Project  string   `json:"project"` // "" = outside any project
	Trifecta Trifecta `json:"trifecta"`
}

// InstrFile is an instruction file the agent reads (CLAUDE.md, AGENTS.md...).
type InstrFile struct {
	Path    string `json:"path"`
	Hidden  int    `json:"hidden"`
	Line    int    `json:"line,omitempty"`
	Decoded string `json:"decoded,omitempty"`
}

// Listener is a TCP port an agent or model server listens on.
type Listener struct {
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
	Public bool   `json:"public"`
}

// Trifecta describes the three capabilities and where each one comes from.
type Trifecta struct {
	Priv     State    `json:"priv"`
	Untr     State    `json:"untr"`
	Out      State    `json:"out"`
	PrivWhy  []string `json:"privWhy,omitempty"`
	UntrWhy  []string `json:"untrWhy,omitempty"`
	OutWhy   []string `json:"outWhy,omitempty"`
	Complete bool     `json:"complete"`
	Scope    string   `json:"scope,omitempty"` // project this trifecta belongs to
}

// Signal is a raw observation from a detector that the rules turn into a finding.
type Signal struct {
	Rule   string
	Detail string
	Fix    string
	Sev    Severity // overrides the rule's severity when set
	Ref
}

// Agent is an AI agent (or model server) found on the machine.
type Agent struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Version     string          `json:"version,omitempty"`
	Binary      string          `json:"binary,omitempty"`
	Running     bool            `json:"running"`
	PIDs        []int           `json:"pids,omitempty"`
	Configs     []string        `json:"configs"`
	Mode        string          `json:"mode,omitempty"`
	Sandbox     string          `json:"sandbox,omitempty"`
	Settings    []Setting       `json:"settings,omitempty"`
	Perms       []Perm          `json:"perms,omitempty"`
	Hooks       []Hook          `json:"hooks,omitempty"`
	MCP         []MCPServer     `json:"mcp"`
	Instr       []InstrFile     `json:"instr,omitempty"`
	Listeners   []Listener      `json:"listeners,omitempty"`
	Extras      []string        `json:"extras,omitempty"`
	ModelHost   bool            `json:"modelHost,omitempty"`
	Mitigations []Mitigation    `json:"mitigations,omitempty"`
	Scopes      []ScopeTrifecta `json:"scopes,omitempty"`
	Grants      []Grant         `json:"-"`
	Base        Trifecta        `json:"-"`
	Trifecta    Trifecta        `json:"trifecta"`
	Risk        int             `json:"risk"`
	Signals     []Signal        `json:"-"`
}

// Flag records a raw observation for the rules engine.
func (a *Agent) Flag(rule, detail, fix string, ref Ref) {
	a.Signals = append(a.Signals, Signal{Rule: rule, Detail: detail, Fix: fix, Ref: ref})
}

// Evidence is one line of proof behind a finding.
type Evidence struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Text string `json:"text"`
}

// Finding is a risk Squadwatch reports.
type Finding struct {
	Key      string     `json:"key"`
	ID       string     `json:"id"`
	Sev      Severity   `json:"sev"`
	Agent    string     `json:"agent"`
	Title    string     `json:"title"`
	Evidence []Evidence `json:"evidence"`
	Why      string     `json:"why"`
	Fix      string     `json:"fix"`
	Refs     []string   `json:"refs,omitempty"`
}

// Path is an attack path: untrusted content → agent → private data → way out.
type Path struct {
	ID     string `json:"id"`
	Agent  string `json:"agent"`
	Scope  string `json:"scope,omitempty"`
	Source string `json:"source"`
	Data   string `json:"data"`
	Sink   string `json:"sink"`
	State  string `json:"state"` // open, partial, cut
}

// Scan is the full result of one run.
type Scan struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Time       time.Time `json:"time"`
	Host       string    `json:"host"`
	OS         string    `json:"os"`
	DurationMS int64     `json:"durationMs"`
	Configs    int       `json:"configsRead"`
	Risk       int       `json:"risk"`
	Agents     []Agent   `json:"agents"`
	Findings   []Finding `json:"findings"`
	Paths      []Path    `json:"paths"`
}

// Agent returns the agent with that id, or nil.
func (s *Scan) Agent(id string) *Agent {
	for i := range s.Agents {
		if s.Agents[i].ID == id {
			return &s.Agents[i]
		}
	}
	return nil
}

// FindingsFor returns the findings attributed to an agent.
func (s *Scan) FindingsFor(id string) []Finding {
	var out []Finding
	for _, f := range s.Findings {
		if f.Agent == id {
			out = append(out, f)
		}
	}
	return out
}

// Count returns how many findings have that severity.
func (s *Scan) Count(sev Severity) int {
	n := 0
	for _, f := range s.Findings {
		if f.Sev == sev {
			n++
		}
	}
	return n
}

// MCPCount returns how many MCP servers are configured across all agents.
func (s *Scan) MCPCount() int {
	n := 0
	for _, a := range s.Agents {
		n += len(a.MCP)
	}
	return n
}
