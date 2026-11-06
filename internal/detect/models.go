package detect

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/sysinfo"
)

// modelServer describes a local model runtime.
type modelServer struct {
	id, name, binary string
	port             int
	dirs             []string
	envVar           string
	unitGlob         string
}

func detectModelServer(e *Env, ms modelServer) *model.Agent {
	bin := e.which(ms.binary, "/usr/local/bin/"+ms.binary, "/usr/bin/"+ms.binary)
	var dir string
	for _, d := range ms.dirs {
		if e.allowed(d) && exists(d) {
			dir = d
			break
		}
	}
	var listeners []sysinfo.Listener
	for _, l := range e.Listeners {
		if l.Port == ms.port {
			listeners = append(listeners, l)
		}
	}
	if bin == "" && dir == "" && len(listeners) == 0 {
		return nil
	}
	a := &model.Agent{ID: ms.id, Name: ms.name, Kind: e.T("Modelos locales"), Binary: e.short(bin), ModelHost: true, Mode: e.T("API HTTP sin autenticación")}

	// Where the listening address was configured, for evidence.
	var confRef model.Ref
	if ms.unitGlob != "" && !e.NoSystem {
		files, _ := filepath.Glob(ms.unitGlob)
		for _, f := range files {
			if ln := grepLine(f, ms.envVar); ln > 0 {
				e.read[f] = true
				a.Configs = append(a.Configs, f)
				confRef = model.Ref{File: f, Line: ln}
			}
		}
	}
	for _, l := range listeners {
		a.Listeners = append(a.Listeners, model.Listener{Addr: l.IP.String(), Port: l.Port, Public: l.Public()})
		if l.Public() {
			ref := confRef
			if ref.File == "" {
				ref = model.Ref{File: e.T("puerto %s:%d", l.IP, l.Port)}
			}
			a.Flag("NET-001", e.T("escucha en %s:%d, accesible desde la red", l.IP, l.Port),
				e.T("Haz que escuche solo en 127.0.0.1 (%s=127.0.0.1) o pon delante un proxy con autenticación.", ms.envVar), ref)
		}
	}
	if dir != "" {
		if n := countFiles(filepath.Join(dir, "models", "manifests")); n > 0 {
			a.Extras = append(a.Extras, e.N(n, "1 modelo descargado", "%d modelos descargados"))
		}
	}
	a.PIDs = e.running(func(p sysinfo.Proc) bool { return p.Base() == ms.binary })
	a.Running = len(a.PIDs) > 0 || len(listeners) > 0
	return a
}

func detectOllama(e *Env) *model.Agent {
	return detectModelServer(e, modelServer{
		id: "ollama", name: "Ollama", binary: "ollama", port: 11434,
		dirs:   []string{e.p(".ollama"), "/usr/share/ollama/.ollama"},
		envVar: "OLLAMA_HOST", unitGlob: "/etc/systemd/system/ollama.service.d/*.conf",
	})
}

func detectLMStudio(e *Env) *model.Agent {
	return detectModelServer(e, modelServer{
		id: "lmstudio", name: "LM Studio", binary: "lms", port: 1234,
		dirs: []string{e.p(".lmstudio"), e.p(".cache", "lm-studio")}, envVar: "host",
	})
}

func grepLine(path, needle string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		if strings.Contains(sc.Text(), needle) {
			return n
		}
	}
	return 0
}

func countFiles(root string) int {
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}
