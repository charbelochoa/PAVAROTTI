package caso

import (
	"encoding/hex"
	"net/netip"
	"strings"
)

type AssetKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func RecordAssets(record Record, network AssetNetwork, kind string, visit func(AssetKey, string)) {
	if item := record.Indicator; item != nil {
		if kind == "" || item.Type == kind {
			if key, valid := NormalizeAsset(AssetKey(*item)); valid {
				visit(key, "indicador")
			}
		}
		return
	}
	if record.Kind == "binario" {
		if kind == "" || kind == "sha256" {
			if value := SHA256Digest(record.SHA256); value != "" {
				visit(AssetKey{Type: "sha256", Value: value}, "muestra")
			}
		}
		return
	}
	withHosts := kind == "" || kind == "dominio" || kind == "ipv4" || kind == "ipv6"
	if record.Traffic != nil {
		if withHosts {
			if host := NetworkHost(record.Source); host != "" {
				visit(AssetHost(host), "observación")
			}
		}
		return
	}
	var role string
	switch record.Kind {
	case "dns":
		role = "observación"
	case "rdap":
		role = "registro"
	case "stix":
		role = "declaración"
	case "hallazgo", "nota":
		role = "referencia"
	default:
		return
	}
	if network.Value != "" && (kind == "" || kind == "red") {
		visit(AssetKey{Type: "red", Value: network.Value}, role)
	}
	if record.Kind == "stix" {
		for _, item := range record.FileHashes {
			if kind != "" && item.Type != kind {
				continue
			}
			if key, valid := NormalizeAsset(AssetKey(item)); valid {
				visit(key, "huella declarada")
			}
		}
	}
	if withHosts {
		if record.Kind == "dns" && (strings.Contains(record.SourceID, "/respuesta/") || strings.Contains(record.SourceID, "/pregunta/")) {
			if len(record.Source) <= 512 {
				first, last, _ := strings.Cut(record.Source, ",")
				owner, valid := NormalizeAsset(AssetHost(strings.TrimSpace(first)))
				if valid {
					visit(owner, role)
				}
				if target, valid := NormalizeAsset(AssetHost(strings.TrimSpace(last))); valid && target != owner {
					visit(target, role)
				}
			}
			return
		}
		for _, host := range SourceHosts(record.Source, record.Kind == "rdap") {
			visit(AssetHost(host), role)
		}
	}
}

func NormalizeAsset(key AssetKey) (AssetKey, bool) {
	if len(key.Value) > 254 {
		return AssetKey{}, false
	}
	value := strings.ToLower(strings.TrimSpace(key.Value))
	switch key.Type {
	case "dominio", "ipv4", "ipv6":
		kind := AssetHost(value)
		if kind.Type == "dominio" {
			name, valid := NormalizeDNSName(value)
			return AssetKey{Type: "dominio", Value: name}, key.Type == "dominio" && valid && name != "."
		}
		return kind, kind.Type == key.Type && kind.Value != ""
	case "md5", "sha1", "sha256":
		if len(value) == map[string]int{"md5": 32, "sha1": 40, "sha256": 64}[key.Type] {
			if _, err := hex.DecodeString(value); err == nil {
				return AssetKey{Type: key.Type, Value: value}, true
			}
		}
	case "red":
		network := ParseAssetNetwork(value)
		return AssetKey{Type: key.Type, Value: network.Value}, network.Value != ""
	}
	return AssetKey{}, false
}

func AssetHost(value string) AssetKey {
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		address = address.Unmap()
		if address.Is4() {
			return AssetKey{Type: "ipv4", Value: address.String()}
		}
		return AssetKey{Type: "ipv6", Value: address.String()}
	}
	return AssetKey{Type: "dominio", Value: value}
}

func (key AssetKey) Cursor() string { return key.Type + "/" + key.Value }
