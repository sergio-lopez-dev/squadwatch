// Package store keeps a history of scans on disk so changes can be compared.
// Scans are already redacted, and the files are only readable by the user.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

const keep = 100

// Dir is where scans are saved: $XDG_DATA_HOME/squadwatch/scans or
// ~/.local/share/squadwatch/scans.
func Dir() string {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "squadwatch", "scans")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".local", "share", "squadwatch", "scans")
}

// Save writes the scan and prunes the oldest ones.
func Save(s *model.Scan) (string, error) {
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, s.Time.UTC().Format("20060102T150405.000Z")+".json")
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	files, _ := List()
	for len(files) > keep {
		_ = os.Remove(files[0])
		files = files[1:]
	}
	return p, nil
}

// List returns saved scans, oldest first.
func List() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(Dir(), "*.json"))
	sort.Strings(files)
	return files, err
}

// Load reads one saved scan.
func Load(p string) (*model.Scan, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s model.Scan
	return &s, json.Unmarshal(b, &s)
}

// ErrNone means there is no saved scan yet.
var ErrNone = errors.New("todavía no hay escaneos guardados")

// Latest returns the most recent saved scan.
func Latest() (*model.Scan, error) {
	files, err := List()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, ErrNone
	}
	return Load(files[len(files)-1])
}

// Point is one entry of the risk history.
type Point struct {
	Time     string `json:"time"`
	Risk     int    `json:"risk"`
	Agents   int    `json:"agents"`
	Findings int    `json:"findings"`
	Crit     int    `json:"crit"`
}

// History summarizes the saved scans, oldest first.
func History() []Point {
	files, _ := List()
	var out []Point
	for _, f := range files {
		s, err := Load(f)
		if err != nil {
			continue
		}
		out = append(out, Point{Time: s.Time.Format("2006-01-02T15:04:05Z07:00"), Risk: s.Risk, Agents: len(s.Agents), Findings: len(s.Findings), Crit: s.Count(model.Crit)})
	}
	return out
}
