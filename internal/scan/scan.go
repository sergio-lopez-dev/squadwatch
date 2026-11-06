// Package scan runs detectors, rules and scoring in order.
package scan

import (
	"os"
	"runtime"
	"time"

	"github.com/sergio-lopez-dev/squadwatch/internal/detect"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/risk"
	"github.com/sergio-lopez-dev/squadwatch/internal/rules"
)

// Version of Squadwatch.
const Version = "0.1.0"

// Run performs a static scan: it reads files and system state, and never
// executes third-party code.
func Run(e *detect.Env) *model.Scan {
	start := time.Now()
	agents := detect.All(e)
	for i := range agents {
		risk.Trifecta(&agents[i])
	}
	findings := rules.Evaluate(agents, e.Home)
	team := risk.Score(agents, findings)
	host, _ := os.Hostname()
	if h := os.Getenv("SQUADWATCH_HOST"); h != "" { // for demos and screenshots
		host = h
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	paths := risk.Paths(agents)
	if paths == nil {
		paths = []model.Path{}
	}
	return &model.Scan{
		Tool:       "squadwatch",
		Version:    Version,
		Time:       start,
		Host:       host,
		OS:         runtime.GOOS,
		DurationMS: time.Since(start).Milliseconds(),
		Configs:    e.ConfigsRead(),
		Risk:       team,
		Agents:     agents,
		Findings:   findings,
		Paths:      paths,
	}
}
