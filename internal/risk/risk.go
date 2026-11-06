// Package risk computes the trifecta, attack paths and risk scores.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/sergio-lopez-dev/squadwatch/internal/model"
)

// Trifecta computes the trifecta of an agent in every project where its
// configuration differs, and keeps the worst one as the agent's trifecta.
//
// Sending data out only counts as "yes" when it happens without
// confirmation and no mitigation (a guard hook, a sandbox) covers it.
func Trifecta(a *model.Agent) {
	if a.ModelHost {
		a.Trifecta = model.Trifecta{Priv: model.No, Untr: model.No, Out: model.No}
		a.Scopes = nil
		return
	}
	var all []model.ScopeTrifecta
	for _, sc := range projects(a) {
		t := compute(a, sc)
		t.Scope = sc
		all = append(all, model.ScopeTrifecta{Project: sc, Trifecta: t})
	}
	best := all[0]
	for _, st := range all[1:] {
		if rank(st.Trifecta) > rank(best.Trifecta) {
			best = st
		}
	}
	a.Trifecta = best.Trifecta
	a.Scopes = nil
	for _, st := range all[1:] {
		if differs(st.Trifecta, all[0].Trifecta) {
			a.Scopes = append(a.Scopes, st)
		}
	}
	if len(a.Scopes) > 0 {
		a.Scopes = append([]model.ScopeTrifecta{all[0]}, a.Scopes...)
	}
}

// projects lists "" (outside any project) plus every project that has its
// own permissions, servers, grants or mitigations.
func projects(a *model.Agent) []string {
	set := map[string]bool{}
	for _, p := range a.Perms {
		set[p.Project] = true
	}
	for _, m := range a.MCP {
		set[m.Project] = true
	}
	for _, g := range a.Grants {
		set[g.Project] = true
	}
	for _, m := range a.Mitigations {
		set[m.Project] = true
	}
	delete(set, "")
	out := []string{""}
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out[1:])
	return out
}

func compute(a *model.Agent, scope string) model.Trifecta {
	t := a.Base
	applies := func(p string) bool { return p == "" || p == scope }
	for _, s := range []*model.State{&t.Priv, &t.Untr, &t.Out} {
		if *s == "" {
			*s = model.No
		}
	}
	privWhy := append([]string(nil), t.PrivWhy...)
	untrWhy := append([]string(nil), t.UntrWhy...)
	var yesOut, partOut []string
	switch t.Out {
	case model.Yes:
		yesOut = append(yesOut, t.OutWhy...)
	case model.Partial:
		partOut = append(partOut, t.OutWhy...)
	}

	var privFirst []string
	for _, g := range a.Grants {
		if !applies(g.Project) {
			continue
		}
		switch g.Cap {
		case model.Priv:
			t.Priv = model.Yes
			privFirst = append(privFirst, g.Reason)
		case model.Untr:
			t.Untr = model.Yes
			untrWhy = append(untrWhy, g.Reason)
		case model.Out:
			if m, ok := mitigated(a, g, scope); ok {
				partOut = append(partOut, g.Reason+" (mitigado: "+m+")")
			} else {
				yesOut = append(yesOut, g.Reason)
			}
		}
	}
	for _, s := range a.MCP {
		if s.Disabled || !applies(s.Project) {
			continue
		}
		label := "MCP " + s.Name
		for _, c := range s.Caps {
			switch c {
			case model.Priv:
				t.Priv = model.Yes
				privWhy = append(privWhy, label)
			case model.Untr:
				t.Untr = model.Yes
				untrWhy = append(untrWhy, label)
			case model.Out:
				if s.AutoApproved {
					yesOut = append(yesOut, label+" (sin confirmación)")
				} else {
					partOut = append(partOut, label+" (con confirmación)")
				}
			}
		}
	}
	t.PrivWhy = unique(append(privFirst, privWhy...))
	t.UntrWhy = unique(untrWhy)
	switch {
	case len(yesOut) > 0:
		t.Out, t.OutWhy = model.Yes, unique(yesOut)
	case len(partOut) > 0:
		t.Out, t.OutWhy = model.Partial, unique(partOut)
	}
	t.Complete = t.Priv == model.Yes && t.Untr == model.Yes && t.Out == model.Yes
	return t
}

// mitigated reports whether a mitigation covers a grant in this scope.
func mitigated(a *model.Agent, g model.Grant, scope string) (string, bool) {
	if g.Kind != "bash" {
		return "", false
	}
	for _, m := range a.Mitigations {
		if m.Covers == "out-bash" && (m.Project == "" || m.Project == scope) {
			return m.Detail, true
		}
	}
	return "", false
}

func rank(t model.Trifecta) int {
	r := 0
	if t.Complete {
		r += 100
	}
	for _, s := range []model.State{t.Priv, t.Untr, t.Out} {
		switch s {
		case model.Yes:
			r += 10
		case model.Partial:
			r++
		}
	}
	return r
}

// differs reports whether a project's trifecta is worth showing on its own:
// different states, or different reasons for being able to send data out or
// read private data.
func differs(a, b model.Trifecta) bool {
	return a.Priv != b.Priv || a.Untr != b.Untr || a.Out != b.Out || a.Complete != b.Complete ||
		strings.Join(a.OutWhy, "|") != strings.Join(b.OutWhy, "|") ||
		strings.Join(a.PrivWhy, "|") != strings.Join(b.PrivWhy, "|")
}

var weight = map[model.Severity]float64{model.Crit: 30, model.High: 15, model.Med: 6, model.Low: 2}

func stateScore(s model.State) float64 {
	switch s {
	case model.Yes:
		return 5
	case model.Partial:
		return 2
	}
	return 0
}

// Score gives every agent a 0–100 risk and returns the team risk.
//
// Points = 30 per critical finding, 15 per high, 6 per medium, 2 per low,
// +2 per extra piece of evidence (up to 3), +5 per trifecta capability the
// agent has without confirmation and +2 per capability that needs it.
//
// Risk = 100 × (1 − e^(−points/60)). The curve never reaches 100, so fixing
// one problem always lowers the number, even on a very exposed agent. An
// agent with a critical finding never drops below 70.
//
// Team risk = 60% the worst agent + 40% the average of agents with risk.
func Score(agents []model.Agent, findings []model.Finding) int {
	for i := range agents {
		a := &agents[i]
		pts := stateScore(a.Trifecta.Priv) + stateScore(a.Trifecta.Untr) + stateScore(a.Trifecta.Out)
		crit := false
		for _, f := range findings {
			if f.Agent != a.ID {
				continue
			}
			extra := len(f.Evidence) - 1
			if extra > 3 {
				extra = 3
			}
			pts += weight[f.Sev] + 2*float64(extra)
			crit = crit || f.Sev == model.Crit
		}
		a.Risk = Curve(pts)
		if crit && a.Risk < 70 {
			a.Risk = 70
		}
	}
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].Risk > agents[j].Risk })
	if len(agents) == 0 {
		return 0
	}
	sum, n := 0, 0
	for _, a := range agents {
		if a.Risk > 0 {
			sum += a.Risk
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return (6*agents[0].Risk + 4*sum/n + 5) / 10
}

// Curve maps risk points to 0–99 with diminishing returns.
func Curve(points float64) int {
	return int(math.Round(100 * (1 - math.Exp(-points/60))))
}

// Paths lists attack paths. An agent gets one path per project where its
// trifecta is complete; otherwise one path for its worst project.
func Paths(agents []model.Agent) []model.Path {
	var out []model.Path
	for _, a := range agents {
		if a.ModelHost {
			continue
		}
		cands := a.Scopes
		if len(cands) == 0 {
			cands = []model.ScopeTrifecta{{Project: a.Trifecta.Scope, Trifecta: a.Trifecta}}
		}
		var picked []model.ScopeTrifecta
		for _, c := range cands {
			if c.Trifecta.Complete {
				picked = append(picked, c)
			}
		}
		if len(picked) == 0 {
			picked = []model.ScopeTrifecta{{Project: a.Trifecta.Scope, Trifecta: a.Trifecta}}
		}
		for _, st := range picked {
			t := st.Trifecta
			if t.Priv != model.Yes || t.Untr != model.Yes {
				continue
			}
			src := specific(t.UntrWhy, "contenido no fiable")
			p := model.Path{Agent: a.ID, Scope: st.Project, Source: src, Data: firstOther(t.PrivWhy, src), Sink: firstOr(t.OutWhy, "sin salida")}
			switch t.Out {
			case model.Yes:
				p.State = "open"
			case model.Partial:
				p.State = "partial"
			default:
				p.State = "cut"
			}
			out = append(out, p)
		}
	}
	order := map[string]int{"open": 0, "partial": 1, "cut": 2}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].State] < order[out[j].State] })
	for i := range out {
		out[i].ID = fmt.Sprintf("P%d", i+1)
	}
	return out
}

// specific prefers a named source (an MCP server, the web) over a generic one.
func specific(xs []string, def string) string {
	for _, x := range xs {
		if strings.HasPrefix(x, "MCP ") {
			return x
		}
	}
	for _, x := range xs {
		if strings.Contains(strings.ToLower(x), "web") {
			return x
		}
	}
	return firstOr(xs, def)
}

// firstOther returns the first item that is not the given one.
func firstOther(xs []string, not string) string {
	for _, x := range xs {
		if x != not {
			return x
		}
	}
	return firstOr(xs, "datos privados")
}

func firstOr(xs []string, def string) string {
	if len(xs) > 0 {
		return xs[0]
	}
	return def
}

func unique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
