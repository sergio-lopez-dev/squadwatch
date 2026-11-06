package detect

import (
	"testing"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

func TestAnalyzePin(t *testing.T) {
	cases := []struct {
		cmd    string
		args   []string
		pinned bool
		pin    string
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-github"}, false, "sin fijar"},
		{"npx", []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"}, true, "2025.4.8"},
		{"npx", []string{"@playwright/mcp@latest"}, false, "@latest"},
		{"npx", []string{"-y", "notion-tools@1.3.2"}, true, "1.3.2"},
		{"uvx", []string{"mcp-server-fetch"}, false, "sin fijar"},
		{"uvx", []string{"mcp-server-fetch==2025.4.7"}, true, "2025.4.7"},
		{"/home/u/.local/bin/uvx", []string{"--python", "3.12", "--with", "mcp<2", "mcp-google-sheets"}, false, "sin fijar"},
		{"docker", []string{"run", "-i", "--rm", "-e", "X=1", "mcp/postgres"}, false, "sin fijar"},
		{"docker", []string{"run", "-i", "mcp/postgres:1.0"}, false, "tag sin digest"},
		{"docker", []string{"run", "-i", "mcp/postgres@sha256:abc"}, true, "digest"},
		{"/usr/bin/node", []string{"/opt/server.js"}, true, "local"},
	}
	for _, c := range cases {
		s := model.MCPServer{Command: c.cmd, Args: c.args}
		analyzePin(&s)
		if s.Pinned != c.pinned || s.Pin != c.pin {
			t.Errorf("%s %v: pin=%q pinned=%v, quería %q %v", c.cmd, c.args, s.Pin, s.Pinned, c.pin, c.pinned)
		}
	}
}

func TestArbitraryCode(t *testing.T) {
	yes := []string{"Bash(node -e ' *)", "Bash(bundle exec *)", "Bash(timeout 150 bin/rails runner ' *)", "Bash(npx *)", "Bash(sudo *)", "Bash(python3 -c *)", "Bash(bash -c *)"}
	no := []string{"Bash(npx eslint *)", "Bash(git checkout *)", "Bash(npm run *)", "Bash(node -e 'console.log(1)')", "Read(//tmp/**)"}
	for _, r := range yes {
		if !arbitraryCode(r) {
			t.Errorf("%s debería permitir código arbitrario", r)
		}
	}
	for _, r := range no {
		if arbitraryCode(r) {
			t.Errorf("%s no debería contar como código arbitrario", r)
		}
	}
}

func TestNetworkWildcard(t *testing.T) {
	if !networkWildcard("Bash(curl *)") || !networkWildcard("Bash(wget:*)") || !networkWildcard("WebFetch") {
		t.Error("los comodines de red deberían detectarse")
	}
	if networkWildcard("Bash(curl -s https://example.com/)") || networkWildcard("WebFetch(domain:example.com)") {
		t.Error("un comando exacto o un dominio concreto no permiten sacar datos arbitrarios")
	}
}

func TestReadsEverything(t *testing.T) {
	home := "/home/u"
	for _, r := range []string{"Read(//home/u/**)", "Read(~/**)", "Read(//**)"} {
		if !readsEverything(r, home) {
			t.Errorf("%s cubre todo el HOME o el disco", r)
		}
	}
	for _, r := range []string{"Read(//home/u/proj/**)", "Read(//tmp/**)", "Read(./src/**)"} {
		if readsEverything(r, home) {
			t.Errorf("%s no cubre todo el HOME", r)
		}
	}
}

func TestNpmVersion(t *testing.T) {
	cases := map[string]string{"pkg": "", "pkg@1.2.3": "1.2.3", "@scope/pkg": "", "@scope/pkg@2.0.0": "2.0.0"}
	for in, want := range cases {
		if got := npmVersion(in); got != want {
			t.Errorf("npmVersion(%q) = %q, quería %q", in, got, want)
		}
	}
}
