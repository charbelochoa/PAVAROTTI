package caso

import (
	"slices"
	"strings"
)

func ValidHTTPRule(rule string) bool {
	return rule != "" && len(rule) <= 64 && !strings.ContainsFunc(rule, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-')
	})
}

func (record Record) MatchesHTTPRule(rule string) bool {
	return rule == "" || (record.Traffic != nil && slices.ContainsFunc(record.HTTPFindings, func(finding HTTPFinding) bool {
		return finding.Rule == rule
	}))
}

func (record Record) HTTPTransportFailure() bool {
	return record.Kind == "tráfico" && record.Traffic != nil && record.Traffic.Status == 502 && record.HTTPRuleSet == 0 &&
		slices.Contains(record.Signals, ProxyNoResponseSignal)
}
