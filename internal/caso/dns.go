package caso

import "strings"

func NormalizeDNSName(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "." {
		return raw, true
	}
	name := strings.TrimSuffix(raw, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return name, true
}
