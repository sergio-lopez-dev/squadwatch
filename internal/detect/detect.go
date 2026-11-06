package detect

import (
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/redact"
)

// detectors in the order agents are listed when risks tie.
var detectors = []func(*Env) *model.Agent{
	detectClaudeCode,
	detectCursor,
	detectCodex,
	detectGemini,
	detectVSCode,
	detectWindsurf,
	detectClaudeDesktop,
	detectAider,
	detectOllama,
	detectLMStudio,
}

// Supported lists the agents Squadwatch knows how to read.
var Supported = []string{"Claude Code", "Cursor", "Codex CLI", "Gemini CLI", "VS Code + Copilot", "Windsurf", "Claude Desktop", "Aider", "Ollama", "LM Studio"}

// All runs every detector and returns the agents found.
func All(e *Env) []model.Agent {
	var out []model.Agent
	for _, d := range detectors {
		if a := d(e); a != nil {
			sanitize(a)
			for i := range a.MCP {
				a.MCP[i].Pin = e.T(a.MCP[i].Pin) // "sin fijar", "remoto"… ; versions pass through
			}
			if a.MCP == nil {
				a.MCP = []model.MCPServer{}
			}
			if a.Configs == nil {
				a.Configs = []string{}
			}
			out = append(out, *a)
		}
	}
	return out
}

// sanitize is a last line of defence: no field may carry a raw secret.
func sanitize(a *model.Agent) {
	for i := range a.Settings {
		a.Settings[i].Value = redact.Text(a.Settings[i].Value)
	}
	for i := range a.Perms {
		a.Perms[i].Rule = redact.Text(a.Perms[i].Rule)
	}
	for i := range a.Hooks {
		a.Hooks[i].Command = redact.Text(a.Hooks[i].Command)
	}
	for i := range a.Signals {
		a.Signals[i].Detail = redact.Text(a.Signals[i].Detail)
	}
}
