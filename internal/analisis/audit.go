package analisis

import (
	"context"

	"pavarotti/internal/caso"
	"pavarotti/internal/revision"
)

func projectAudit(record *caso.Record, base caso.Record) {
	if review := base.StaticReview(); review != nil {
		projected := caso.CodeReview{Package: clip(review.Package, 160), Engine: clip(review.Engine, 32), Total: review.Total}
		for _, item := range review.Signals[:min(len(review.Signals), revision.MaxFindings)] {
			if item.Line > 0 && item.Column > 0 && item.Rule != "" {
				projected.Signals = append(projected.Signals, caso.Finding{Rule: clip(item.Rule, 80), Line: item.Line, Column: item.Column})
			}
		}
		record.Review = &projected
	}
	if inventory := base.Dependencies; base.Kind == "dependencias" && inventory != nil {
		projected := caso.DependencyInventory{Ecosystem: clip(inventory.Ecosystem, 16), Manifest: clip(inventory.Manifest, 64)}
		for _, component := range inventory.Entries[:min(len(inventory.Entries), revision.MaxDependencies)] {
			entry := caso.Dependency{Name: clip(component.Name, 255), Version: clip(component.Version, 128),
				Line: component.Line, Location: clip(component.Location, 2400)}
			if replacement := component.Replacement; replacement != nil {
				entry.Replacement = &caso.Replacement{Name: clip(replacement.Name, 255), Version: clip(replacement.Version, 128), Local: replacement.Local}
			}
			projected.Entries = append(projected.Entries, entry)
		}
		record.Dependencies = &projected
	}
}

func summarizeAudit(ctx context.Context, observations []observation) result {
	findings, dependencies := make(groups), make(groups)
	reviewed := 0
	for _, item := range observations {
		if err := ctx.Err(); err != nil {
			return result{err: err}
		}
		if review := item.record.StaticReview(); review != nil {
			reviewed++
			for _, finding := range review.Signals {
				ref := item.ref
				ref.Line, ref.Column = finding.Line, finding.Column
				findings.add(groupKey{value: finding.Rule, scope: "go"}, ref)
			}
		}
		if inventory := item.record.Dependencies; inventory != nil {
			reviewed++
			for _, component := range inventory.Entries {
				ref := item.ref
				ref.Line, ref.Location = component.Line, component.Location
				scope := inventory.Ecosystem
				if component.Version != "" {
					scope += " · " + component.Version
				}
				if replacement := component.Replacement; replacement != nil {
					if replacement.Local {
						scope += " · reemplazo local"
					} else {
						scope += " · usa " + replacement.Name + " " + replacement.Version
					}
				}
				dependencies.add(groupKey{value: component.Name, scope: scope}, ref)
			}
		}
	}
	return result{apply: func(report *Report) {
		report.CodeFindings, report.Dependencies = findings.top(), dependencies.top()
		report.Agents = append(report.Agents, AgentResult{Name: "Revisión de código y dependencias", Reviewed: reviewed,
			Matched: len(findings) + len(dependencies), Shown: len(report.CodeFindings) + len(report.Dependencies)})
	}}
}
