package caso

import (
	"encoding/hex"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

func SourceHosts(source string, allowSingleLabel bool) []string {
	if len(source) > 16<<10 {
		return nil
	}
	seen := make(map[string]bool)
	var hosts []string
	for part := range strings.SplitSeq(source, ",") {
		host := NetworkHost(part)
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

func NetworkHost(value string) string {
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

func SHA256Digest(input string) string {
	if len(input) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(input); err != nil {
		return ""
	}
	return strings.ToLower(input)
}
