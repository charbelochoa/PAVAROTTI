package caso

import (
	"net/netip"
	"strings"
)

type AssetNetwork struct {
	Value  string
	Prefix netip.Prefix
	Start  netip.Addr
	End    netip.Addr
}

func RecordNetwork(record Record) AssetNetwork {
	if record.Kind != "rdap" && record.Kind != "stix" {
		return AssetNetwork{}
	}
	value := record.Network
	if value == "" {
		if old, ok := strings.CutPrefix(record.Title, "Red · "); ok {
			value = old
		}
	}
	return ParseAssetNetwork(value)
}

func ParseAssetNetwork(value string) AssetNetwork {
	if value == "" || len(value) > 85 {
		return AssetNetwork{}
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && !prefix.Addr().Is4In6() {
		prefix = prefix.Masked()
		return AssetNetwork{Prefix: prefix, Value: prefix.String()}
	}
	left, right, ok := strings.Cut(value, "–")
	if !ok {
		return AssetNetwork{}
	}
	start, startErr := netip.ParseAddr(strings.TrimSpace(left))
	end, endErr := netip.ParseAddr(strings.TrimSpace(right))
	if startErr != nil || endErr != nil || start.Zone() != "" || end.Zone() != "" || start.Is4In6() || end.Is4In6() ||
		start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return AssetNetwork{}
	}
	return AssetNetwork{Start: start, End: end, Value: start.String() + " – " + end.String()}
}

func (network AssetNetwork) Contains(address netip.Addr) bool {
	if network.Prefix.IsValid() {
		return network.Prefix.Contains(address)
	}
	return network.Start.IsValid() && address.BitLen() == network.Start.BitLen() &&
		network.Start.Compare(address) <= 0 && network.End.Compare(address) >= 0
}
