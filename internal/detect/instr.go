package detect

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/redact"
)

// isHidden reports characters a person cannot see but a model reads:
// Unicode tag characters, zero-width spaces and bidirectional overrides.
func isHidden(r rune) bool {
	switch {
	case r >= 0xE0000 && r <= 0xE007F: // tag characters (ASCII smuggling)
		return true
	case r == 0x200B || r == 0x200C: // zero-width space / non-joiner
		return true
	case r >= 0x2060 && r <= 0x2064: // word joiner, invisible operators
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi overrides
		return true
	}
	return false
}

// scanInstr checks an instruction file for hidden text.
func (e *Env) scanInstr(path string) (model.InstrFile, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > 2<<20 {
		return model.InstrFile{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.InstrFile{}, false
	}
	e.read[path] = true
	f := model.InstrFile{Path: e.short(path)}
	line := 1
	var decoded []rune
	for i, r := range string(raw) {
		if r == '\n' {
			line++
			continue
		}
		if i == 0 && r == 0xFEFF {
			continue
		}
		if isHidden(r) {
			f.Hidden++
			if f.Line == 0 {
				f.Line = line
			}
			if r >= 0xE0020 && r <= 0xE007E && len(decoded) < 200 {
				decoded = append(decoded, r-0xE0000)
			}
		}
	}
	if len(decoded) > 0 {
		f.Decoded = redact.Text(string(decoded))
	}
	return f, true
}

// addInstr scans the given files and attaches the ones that exist.
func (e *Env) addInstr(a *model.Agent, paths ...string) {
	for _, p := range paths {
		if f, ok := e.scanInstr(p); ok {
			a.Instr = append(a.Instr, f)
		}
	}
}

// scanTree scans every file under root accepted by match, up to limit files.
// It returns how many it scanned; only files with hidden text are attached.
func (e *Env) scanTree(a *model.Agent, root string, match func(name string) bool, limit int) int {
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || n >= limit {
			return filepath.SkipDir
		}
		if d.IsDir() {
			if name := d.Name(); strings.HasPrefix(name, ".") && p != root || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !match(d.Name()) {
			return nil
		}
		n++
		if f, ok := e.scanInstr(p); ok && f.Hidden > 0 {
			a.Instr = append(a.Instr, f)
		}
		return nil
	})
	return n
}
