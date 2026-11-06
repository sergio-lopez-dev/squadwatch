package main

import (
	"github.com/sergio-lopez-dev/squadwatch/internal/report"
	"github.com/sergio-lopez-dev/squadwatch/internal/rules"
)

func rulesCatalog() [][]string {
	var out [][]string
	for _, r := range rules.Catalog {
		out = append(out, []string{r.ID, report.Sev(r.Sev), r.Title})
	}
	return out
}
