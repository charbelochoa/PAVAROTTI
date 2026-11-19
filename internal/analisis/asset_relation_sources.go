package analisis

import (
	"net/netip"
	"strings"

	"pavarotti/internal/caso"
)

func recordAssetRelations(record caso.Record, anchor AssetKey, address netip.Addr, network assetNetwork, emit func(assetRelationKey)) {
	link := func(source, target AssetKey, kind string) {
		if source == target {
			return
		}
		switch anchor {
		case source:
			emit(assetRelationKey{asset: target, kind: kind, direction: "saliente"})
		case target:
			emit(assetRelationKey{asset: source, kind: kind, direction: "entrante"})
		}
	}
	if address.IsValid() {
		rangeOfRecord := recordNetwork(record)
		if rangeOfRecord.contains(address) {
			link(AssetKey{Type: "red", Value: rangeOfRecord.value}, anchor, record.Kind+"-cobertura")
		}
	}
	if network.value != "" {
		for _, observed := range observedNetworkAddresses(record, network) {
			link(anchor, hostAsset(observed.String()), "ip-observada")
		}
	}
	switch record.Kind {
	case "dns":
		if anchor.Type == "dominio" || address.IsValid() {
			if source, destination, kind, ok := dnsAssetPair(record); ok {
				link(source, destination, kind)
			}
		}
	case "rdap":
		if anchor.Type == "dominio" && record.Network == "" {
			owner, ok := strings.CutPrefix(record.Title, "Dominio · ")
			if !ok {
				return
			}
			hosts := sourceHosts(record.Source, true)
			if len(hosts) < 2 || hosts[0] != owner || hostAsset(owner).Type != "dominio" {
				return
			}
			source := hostAsset(owner)
			for _, host := range hosts[1:] {
				server := hostAsset(host)
				if server.Type == "dominio" {
					link(source, server, "rdap-ns")
				}
			}
		}
	case "stix":
		if (anchor.Type == "sha256" || anchor.Type == "sha1" || anchor.Type == "md5") &&
			len(record.FileHashes) > 1 && strings.HasPrefix(record.STIXObject().ID, "file--") {
			relatedFileHashes(record.FileHashes, anchor, emit)
		}
	}
}

func dnsAssetPair(record caso.Record) (AssetKey, AssetKey, string, bool) {
	if len(record.Source) > 512 || !strings.Contains(record.SourceID, "/respuesta/") {
		return AssetKey{}, AssetKey{}, "", false
	}
	rr, owner, _ := strings.Cut(record.Title, " ")
	source, target, found := strings.Cut(record.Source, ",")
	origin, valid := normalizeAsset(AssetKey{Type: "dominio", Value: source})
	if !found || !valid || origin.Value != owner {
		return AssetKey{}, AssetKey{}, "", false
	}
	var destination AssetKey
	switch rr {
	case "A", "AAAA":
		address, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil || address.Zone() != "" || (rr == "A" && !address.Is4()) || (rr == "AAAA" && !address.Is6()) {
			return AssetKey{}, AssetKey{}, "", false
		}
		destination = hostAsset(address.Unmap().String())
	case "CNAME", "NS", "PTR", "MX", "SRV":
		destination, valid = normalizeAsset(AssetKey{Type: "dominio", Value: target})
		if !valid {
			return AssetKey{}, AssetKey{}, "", false
		}
	default:
		return AssetKey{}, AssetKey{}, "", false
	}
	return origin, destination, "dns-" + strings.ToLower(rr), true
}

func relatedFileHashes(hashes []caso.Indicator, anchor AssetKey, emit func(assetRelationKey)) {
	seen := make(map[AssetKey]bool)
	for _, hash := range hashes {
		switch hash.Type {
		case "sha256", "sha1", "md5":
			if key, valid := normalizeAsset(AssetKey(hash)); valid {
				seen[key] = true
			}
		}
	}
	if !seen[anchor] {
		return
	}
	delete(seen, anchor)
	for key := range seen {
		emit(assetRelationKey{asset: key, kind: "stix-huella", direction: "compartida"})
	}
}
