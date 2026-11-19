package analisis

import (
	"net/netip"
	"strings"

	"pavarotti/internal/caso"
)

type assetNetwork struct {
	value  string
	prefix netip.Prefix
	start  netip.Addr
	end    netip.Addr
}

func recordNetwork(record caso.Record) assetNetwork {
	if record.Kind != "rdap" && record.Kind != "stix" {
		return assetNetwork{}
	}
	value := record.Network
	if value == "" {
		if old, ok := strings.CutPrefix(record.Title, "Red · "); ok {
			value = old
		}
	}
	return parseAssetNetwork(value)
}

func parseAssetNetwork(value string) assetNetwork {
	if value == "" || len(value) > 85 {
		return assetNetwork{}
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && !prefix.Addr().Is4In6() {
		prefix = prefix.Masked()
		return assetNetwork{prefix: prefix, value: prefix.String()}
	}
	left, right, ok := strings.Cut(value, "–")
	if !ok {
		return assetNetwork{}
	}
	start, startErr := netip.ParseAddr(strings.TrimSpace(left))
	end, endErr := netip.ParseAddr(strings.TrimSpace(right))
	if startErr != nil || endErr != nil || start.Zone() != "" || end.Zone() != "" || start.Is4In6() || end.Is4In6() ||
		start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return assetNetwork{}
	}
	return assetNetwork{start: start, end: end, value: start.String() + " – " + end.String()}
}

func (network assetNetwork) contains(address netip.Addr) bool {
	if network.prefix.IsValid() {
		return network.prefix.Contains(address)
	}
	return network.start.IsValid() && address.BitLen() == network.start.BitLen() &&
		network.start.Compare(address) <= 0 && network.end.Compare(address) >= 0
}
