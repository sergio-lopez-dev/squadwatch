// Package mcpcat classifies MCP servers by what they let an agent do.
//
// The catalog matches on the server name, command, arguments and URL. A
// server that matches nothing is marked unknown rather than guessed.
package mcpcat

import (
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

type entry struct {
	kind  string
	match []string
	caps  []model.Cap
}

var (
	priv = model.Priv
	untr = model.Untr
	out  = model.Out
)

// Order matters: the first match wins, so specific names go first.
var catalog = []entry{
	{"github", []string{"server-github", "github-mcp", "github"}, []model.Cap{priv, untr, out}},
	{"gitlab", []string{"gitlab"}, []model.Cap{priv, untr, out}},
	{"filesystem", []string{"server-filesystem", "filesystem"}, []model.Cap{priv}},
	{"fetch", []string{"mcp-server-fetch", "server-fetch", "fetch"}, []model.Cap{untr, out}},
	{"browser", []string{"playwright", "puppeteer", "browserbase", "chrome-devtools", "browser"}, []model.Cap{untr, out}},
	{"search", []string{"brave-search", "tavily", "exa-mcp", "perplexity", "serper", "web-search", "websearch"}, []model.Cap{untr, out}},
	{"messaging", []string{"slack", "discord", "telegram", "whatsapp", "gmail", "outlook", "email"}, []model.Cap{priv, untr, out}},
	{"work", []string{"notion", "linear", "jira", "atlassian", "confluence", "asana", "trello", "clickup"}, []model.Cap{priv, untr}},
	{"google-workspace", []string{"google-drive", "gdrive", "google-sheets", "google-docs", "gsheets"}, []model.Cap{priv, untr}},
	{"database", []string{"postgres", "mysql", "sqlite", "mongodb", "redis", "supabase", "bigquery", "snowflake", "clickhouse"}, []model.Cap{priv}},
	{"cloud", []string{"aws", "gcloud", "google-cloud", "azure", "kubernetes", "kubectl", "terraform", "cloudflare"}, []model.Cap{priv, out}},
	{"observability", []string{"sentry", "datadog", "grafana"}, []model.Cap{priv}},
	{"design", []string{"figma"}, []model.Cap{priv}},
	{"docs", []string{"context7", "deepwiki", "docs-mcp"}, []model.Cap{untr}},
	{"memory", []string{"server-memory", "memory"}, []model.Cap{priv}},
}

// Classify fills Kind, Caps and Known.
func Classify(s *model.MCPServer) {
	hay := strings.ToLower(strings.Join(append([]string{s.Name, s.Command, s.URL}, s.Args...), " "))
	for _, e := range catalog {
		for _, m := range e.match {
			if strings.Contains(hay, m) {
				s.Kind = e.kind
				s.Caps = append([]model.Cap(nil), e.caps...)
				s.Known = true
				return
			}
		}
	}
	s.Kind = "desconocido"
	s.Caps = []model.Cap{}
	s.Known = false
}
