package analisis

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type groupKey struct {
	value string
	scope string
}

type groups map[groupKey]*Group

func (g groups) add(key groupKey, ref Evidence) {
	group := g[key]
	if group == nil {
		group = &Group{Value: key.value, Scope: key.scope}
		g[key] = group
	}
	group.Count++
	if len(group.Evidence) < referenceLimit {
		group.Evidence = append(group.Evidence, ref)
	}
}

func (g groups) top() []Group {
	result := make([]Group, 0, len(g))
	for _, value := range g {
		result = append(result, *value)
	}
	slices.SortFunc(result, func(a, b Group) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		if a.Value != b.Value {
			return strings.Compare(a.Value, b.Value)
		}
		return strings.Compare(a.Scope, b.Scope)
	})
	return result[:min(len(result), groupLimit)]
}

func inventory(ctx context.Context, observations []observation) result {
	assets, hashes, indicators := make(groups), make(groups), make(groups)
	for _, item := range observations {
		if err := ctx.Err(); err != nil {
			return result{err: err}
		}
		if item.record.Indicator == nil {
			for _, host := range observedHosts(item.record.Source) {
				assets.add(groupKey{value: host}, item.ref)
			}
		}
		if item.ref.SHA256 != "" {
			hashes.add(groupKey{value: item.ref.SHA256, scope: item.ref.Kind}, item.ref)
		}
		if indicator := item.record.Indicator; indicator != nil && indicator.Value != "" {
			indicators.add(groupKey{value: clip(indicator.Value, 253), scope: clip(indicator.Type, 32)}, item.ref)
		}
	}
	matches := make(groups)
	for key, entry := range indicators {
		if observed := assets[groupKey{value: key.value}]; observed != nil {
			matches[key] = &Group{Value: key.value, Scope: key.scope, Count: observed.Count}
			matches[key].Evidence = append(matches[key].Evidence, entry.Evidence[0])
			matches[key].Evidence = append(matches[key].Evidence, observed.Evidence[:min(len(observed.Evidence), referenceLimit-1)]...)
		}
	}
	assetGroups, hashGroups := assets.top(), hashes.top()
	return result{apply: func(report *Report) {
		report.Assets, report.Hashes = assetGroups, hashGroups
		report.Indicators = indicators.top()
		report.Matches = matches.top()
		report.Agents = append(report.Agents, AgentResult{
			Name: "Inventario", Reviewed: len(observations), Matched: len(assets) + len(hashes) + len(indicators) + len(matches),
			Shown: len(report.Assets) + len(report.Hashes) + len(report.Indicators) + len(report.Matches),
		})
	}}
}

func httpSignals(ctx context.Context, observations []observation) result {
	signals, responses := make(groups), make(groups)
	reviewed := 0
	for _, item := range observations {
		if err := ctx.Err(); err != nil {
			return result{err: err}
		}
		if item.record.Traffic == nil {
			continue
		}
		reviewed++
		host := networkHost(item.record.Source)
		if status := item.record.Traffic.Status; status >= 100 && status <= 599 {
			responses.add(groupKey{value: strconv.Itoa(status), scope: host}, item.ref)
		}
		seen := make(map[string]bool)
		for _, raw := range item.record.Signals[:min(len(item.record.Signals), 32)] {
			label := clip(raw, 160)
			if label != "" && !seen[label] {
				signals.add(groupKey{value: label, scope: host}, item.ref)
				seen[label] = true
			}
		}
	}
	signalGroups, responseGroups := signals.top(), responses.top()
	return result{apply: func(report *Report) {
		report.Signals, report.Responses = signalGroups, responseGroups
		report.Agents = append(report.Agents, AgentResult{
			Name: "Correlación HTTP", Reviewed: reviewed, Matched: len(signals) + len(responses),
			Shown: len(report.Signals) + len(report.Responses),
		})
	}}
}

func chronology(ctx context.Context, observations []observation) result {
	timeline := make([]Evidence, 0, min(len(observations), timelineLimit))
	matched := 0
	for _, item := range observations {
		if err := ctx.Err(); err != nil {
			return result{err: err}
		}
		if !item.date.IsZero() {
			matched++
			if len(timeline) < timelineLimit {
				timeline = append(timeline, item.ref)
			}
		}
	}
	return result{apply: func(report *Report) {
		report.Timeline = timeline
		report.Agents = append(report.Agents, AgentResult{
			Name: "Cronología", Reviewed: len(observations), Matched: matched, Shown: len(timeline),
		})
	}}
}

func observedHosts(source string) []string {
	return sourceHosts(source, false)
}

func sourceHosts(source string, allowSingleLabel bool) []string {
	if len(source) > 16<<10 {
		return nil
	}
	seen := make(map[string]bool)
	var hosts []string
	for part := range strings.SplitSeq(source, ",") {
		host := networkHost(part)
		if host == "" && allowSingleLabel {
			host = namedHost(strings.TrimSpace(part))
		}
		if host != "" && !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
			if len(hosts) == 32 {
				break
			}
		}
	}
	return hosts
}

func networkHost(value string) string {
	input := strings.TrimSpace(value)
	if input == "" || len(input) > 2048 {
		return ""
	}
	explicit := strings.Contains(input, "://")
	if explicit {
		parsed, err := url.Parse(input)
		if err != nil || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
			return ""
		}
		input = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
		explicit = true
	} else if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		input = input[1 : len(input)-1]
	}
	if address, err := netip.ParseAddr(input); err == nil {
		return address.WithZone("").Unmap().String()
	}
	if !explicit && !strings.Contains(strings.TrimSuffix(input, "."), ".") {
		return ""
	}
	return namedHost(input)
}

func namedHost(input string) string {
	host := strings.ToLower(strings.TrimSuffix(input, "."))
	if len(host) > 253 {
		return ""
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return ""
			}
		}
	}
	return host
}

func digest(input string) string {
	if len(input) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(input); err != nil {
		return ""
	}
	return strings.ToLower(input)
}

func clip(value string, limit int) string {
	var output strings.Builder
	for _, char := range strings.TrimSpace(value) {
		if unicode.IsControl(char) || unicode.In(char, unicode.Cf) {
			char = ' '
		}
		if output.Len()+utf8.RuneLen(char) > limit {
			break
		}
		output.WriteRune(char)
	}
	return output.String()
}
