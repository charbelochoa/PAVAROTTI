package analisis

import (
	"context"
	"net/netip"
	"slices"
	"sort"

	"pavarotti/internal/caso"
)

type networkSource struct {
	network caso.AssetNetwork
	ref     Evidence
}

func correlateEvidence(ctx context.Context, observations []observation) result {
	binaries := make(groups)
	indicators := make(map[string]Evidence)
	addresses := make(map[netip.Addr]Evidence)
	networks := make(map[groupKey]networkSource)
	for _, item := range observations {
		if err := ctx.Err(); err != nil {
			return result{err: err}
		}
		record := item.record
		if record.Kind == "binario" && item.ref.SHA256 != "" {
			binaries.add(groupKey{value: item.ref.SHA256}, item.ref)
		}
		if indicator := record.Indicator; indicator != nil {
			if indicator.Type == "sha256" {
				value := caso.SHA256Digest(indicator.Value)
				if _, found := indicators[value]; value != "" && !found {
					indicators[value] = item.ref
				}
			}
			continue
		}
		if network := caso.RecordNetwork(record); network.Value != "" {
			key := groupKey{value: network.Value, scope: record.Kind}
			if _, found := networks[key]; !found {
				networks[key] = networkSource{network: network, ref: item.ref}
			}
		}
		if record.Kind == "dns" || record.Traffic != nil {
			for _, host := range observedHosts(record.Source) {
				if address, err := netip.ParseAddr(host); err == nil {
					if _, found := addresses[address]; !found {
						addresses[address] = item.ref
					}
				}
			}
		}
	}
	hashMatches := make(groups)
	for key, samples := range binaries {
		if indicator, found := indicators[key.value]; found {
			entries := append([]Evidence{indicator}, samples.Evidence[:min(len(samples.Evidence), referenceLimit-1)]...)
			hashMatches[key] = &Group{Value: key.value, Scope: "sha256", Count: samples.Count, Evidence: entries}
		}
	}
	networkMatches, err := coveredAddresses(ctx, networks, addresses)
	if err != nil {
		return result{err: err}
	}
	return result{apply: func(report *Report) {
		report.HashMatches, report.NetworkMatches = hashMatches.top(), networkMatches.top()
		report.Agents = append(report.Agents, AgentResult{Name: "Correlación de muestras y redes", Reviewed: len(observations),
			Matched: len(hashMatches) + len(networkMatches), Shown: len(report.HashMatches) + len(report.NetworkMatches)})
	}}
}

func coveredAddresses(ctx context.Context, networks map[groupKey]networkSource, addresses map[netip.Addr]Evidence) (groups, error) {
	ordered := make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		ordered = append(ordered, address)
	}
	slices.SortFunc(ordered, netip.Addr.Compare)
	matches := make(groups)
	for key, source := range networks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first := source.network.Start
		if source.network.Prefix.IsValid() {
			first = source.network.Prefix.Addr()
		}
		start := sort.Search(len(ordered), func(i int) bool { return ordered[i].Compare(first) >= 0 })
		tail := ordered[start:]
		count := sort.Search(len(tail), func(i int) bool { return !source.network.Contains(tail[i]) })
		if count == 0 {
			continue
		}
		group := &Group{Value: key.value, Scope: key.scope, Count: count, Evidence: []Evidence{source.ref}}
		for _, address := range tail[:min(count, referenceLimit-1)] {
			group.Samples = append(group.Samples, address.String())
			if ref := addresses[address]; !slices.Contains(group.Evidence, ref) {
				group.Evidence = append(group.Evidence, ref)
			}
		}
		matches[key] = group
	}
	return matches, nil
}
