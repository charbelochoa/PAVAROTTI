package analisis

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

var (
	ErrSTIXEmpty = errors.New("no hay evidencia compatible con la exportación STIX")
	ErrSTIXLimit = errors.New("la exportación STIX admite hasta 5000 objetos y 32 MiB; acota los filtros")
)

type STIXExportStats struct {
	Exported int
	Excluded int
	Objects  int
}

func (stats STIXExportStats) Message() string {
	return fmt.Sprintf("STIX · %d objetos · %d registros representados · %d fuera del formato", stats.Objects, stats.Exported, stats.Excluded)
}

type exchangeBundle struct {
	Type    string           `json:"type"`
	ID      string           `json:"id"`
	Objects []*exchangeEntry `json:"objects"`
}

type exchangeEntry struct {
	Type           string            `json:"type"`
	ID             string            `json:"id"`
	Version        string            `json:"spec_version"`
	Created        string            `json:"created,omitempty"`
	Modified       string            `json:"modified,omitempty"`
	Origins        []caso.STIXOrigin `json:"external_references,omitempty"`
	Value          string            `json:"value,omitempty"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	Resolves       []string          `json:"resolves_to_refs,omitempty"`
	Belongs        []string          `json:"belongs_to_refs,omitempty"`
	Pattern        string            `json:"pattern,omitempty"`
	PatternType    string            `json:"pattern_type,omitempty"`
	PatternVersion string            `json:"pattern_version,omitempty"`
	ValidFrom      string            `json:"valid_from,omitempty"`
	First          string            `json:"first_observed,omitempty"`
	Last           string            `json:"last_observed,omitempty"`
	Count          int               `json:"number_observed,omitempty"`
	Refs           []string          `json:"object_refs,omitempty"`
	Content        string            `json:"content,omitempty"`
	Relationship   string            `json:"relationship_type,omitempty"`
	Source         string            `json:"source_ref,omitempty"`
	Target         string            `json:"target_ref,omitempty"`
}

type exchangeTarget struct{ scope, id string }

type exchangeLinks struct {
	entry *exchangeEntry
	scope string
	refs  []caso.STIXRef
}

type stixBuilder struct {
	entries []*exchangeEntry
	scos    map[string]*exchangeEntry
	targets map[string][]exchangeTarget
	links   []exchangeLinks
	stats   STIXExportStats
}

var stixRelationType = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

func ExportSTIX(ctx context.Context, store *caso.Store, include func(caso.Record) bool) ([]byte, STIXExportStats, error) {
	build := stixBuilder{scos: make(map[string]*exchangeEntry), targets: make(map[string][]exchangeTarget)}
	seen := 0
	err := store.Walk(ctx, func(record caso.Record) error {
		if include != nil && !include(record) {
			return nil
		}
		if seen == RecordLimit {
			return ErrSTIXLimit
		}
		seen++
		before := len(build.entries)
		build.add(record)
		if len(build.entries) > caso.MaxSTIXObjects {
			return ErrSTIXLimit
		}
		if len(build.entries) == before {
			build.stats.Excluded++
		} else {
			build.stats.Exported++
		}
		return nil
	})
	if err != nil {
		return nil, STIXExportStats{}, err
	}
	if len(build.entries) == 0 {
		return nil, build.stats, ErrSTIXEmpty
	}
	for _, links := range build.links {
		if err := ctx.Err(); err != nil {
			return nil, STIXExportStats{}, err
		}
		build.connect(links)
	}
	build.stats.Objects = len(build.entries)
	data, err := json.MarshalIndent(exchangeBundle{Type: "bundle", ID: newSTIXID("bundle"), Objects: build.entries}, "", "  ")
	if len(data)+1 > 32<<20 {
		return nil, STIXExportStats{}, ErrSTIXLimit
	}
	return append(data, '\n'), build.stats, err
}

func (build *stixBuilder) add(record caso.Record) {
	object := record.STIXObject()
	entry := &exchangeEntry{Version: "2.1"}
	date, timeErr := time.Parse(time.RFC3339Nano, record.Time)
	if timeErr != nil {
		date = time.Now().UTC()
	}
	entry.Created = date.UTC().Format("2006-01-02T15:04:05.000Z")
	entry.Modified = entry.Created
	entry.Origins = []caso.STIXOrigin{evidenceOrigin(record, object.ID)}
	for _, prior := range object.Origins {
		if prior.Valid() && !slices.Contains(entry.Origins, prior) && len(entry.Origins) < 8 {
			entry.Origins = append(entry.Origins, prior)
		}
	}
	var originalTarget string
	switch stixKind(object.ID) {
	case "relationship":
		kind, _ := strings.CutPrefix(record.Title, "Relación · ")
		if !stixRelationType.MatchString(kind) || !stixEndpoint(refByRole(object.Refs, "origen")) ||
			!stixEndpoint(refByRole(object.Refs, "destino")) {
			return
		}
		entry.Type, entry.Relationship = "relationship", kind
	case "observed-data":
		if !validObservation(object.Observation) || !validObservedRefs(object.Refs) {
			return
		}
		entry.Type = "observed-data"
		entry.First, entry.Last, entry.Count = object.Observation.First, object.Observation.Last, object.Observation.Count
	case "note":
		if refByRole(object.Refs, "anotado") == "" {
			return
		}
		entry.Type, entry.Content = "note", "Procedencia de evidencia del expediente PAVAROTTI."
	default:
		if record.Indicator != nil {
			key, valid := normalizeAsset(AssetKey(*record.Indicator))
			if !valid {
				return
			}
			field := stixSCOType(key.Type) + ":value"
			if algorithm := stixHashName(key.Type); algorithm != "" {
				field = "file:hashes.'" + algorithm + "'"
			}
			entry.Type, entry.ValidFrom = "indicator", entry.Created
			entry.Pattern, entry.PatternType, entry.PatternVersion = fmt.Sprintf("[%s = '%s']", field, key.Value), "stix", "2.1"
			break
		}
		entry.Refs = build.observables(record)
		if len(entry.Refs) == 0 {
			return
		}
		if record.Kind == "stix" {
			originalTarget = entry.Refs[0]
			if refs := object.Refs; len(refs) > 0 {
				build.links = append(build.links, exchangeLinks{build.scos[originalTarget], record.SHA256, refs})
			}
		}
		if timeErr == nil && (record.Kind == "dns" || record.Traffic != nil) {
			entry.Type, entry.Count = "observed-data", 1
			entry.First = date.UTC().Format(time.RFC3339Nano)
			entry.Last = entry.First
		} else {
			entry.Type, entry.Content = "note", "Procedencia de evidencia del expediente PAVAROTTI."
			if network := recordNetwork(record); network.value != "" {
				entry.Content += " Red declarada: " + network.value
			}
		}
	}
	entry.ID = newSTIXID(entry.Type)
	build.entries = append(build.entries, entry)
	if object.ID != "" {
		if originalTarget == "" {
			originalTarget = entry.ID
			build.links = append(build.links, exchangeLinks{entry, record.SHA256, object.Refs})
		}
		build.targets[object.ID] = append(build.targets[object.ID], exchangeTarget{record.SHA256, originalTarget})
	}
}

func (build *stixBuilder) observables(record caso.Record) []string {
	if record.Kind != "dns" && record.Kind != "rdap" && record.Kind != "stix" && record.Kind != "binario" && record.Traffic == nil {
		return nil
	}
	var ids []string
	hashes := make(map[string]string)
	network := recordNetwork(record)
	recordAssets(record, network, "", func(key AssetKey, _ string) {
		if kind := stixSCOType(key.Type); kind != "" {
			ids = appendDistinct(ids, build.sco(&exchangeEntry{Type: kind, Value: key.Value}))
		} else if algorithm := stixHashName(key.Type); algorithm != "" {
			hashes[algorithm] = key.Value
		}
	})
	for _, prefix := range networkPrefixes(network) {
		kind := "ipv6-addr"
		if prefix.Addr().Is4() {
			kind = "ipv4-addr"
		}
		ids = appendDistinct(ids, build.sco(&exchangeEntry{Type: kind, Value: prefix.String()}))
	}
	if len(hashes) > 0 {
		ids = appendDistinct(ids, build.sco(&exchangeEntry{Type: "file", Hashes: hashes}))
	}
	return ids
}

func (build *stixBuilder) connect(links exchangeLinks) {
	row := links.entry
	for _, ref := range links.refs {
		id := build.resolve(ref.ID, links.scope)
		switch ref.Role {
		case "origen":
			row.Source = id
		case "destino":
			row.Target = id
		case "observado", "anotado":
			row.Refs = appendDistinct(row.Refs, id)
		case "resuelve a":
			if canResolveSTIX(row.Type, stixKind(id)) {
				row.Resolves = appendDistinct(row.Resolves, id)
			}
		case "pertenece a":
			if (row.Type == "ipv4-addr" || row.Type == "ipv6-addr") && stixKind(id) == "autonomous-system" {
				row.Belongs = appendDistinct(row.Belongs, id)
			}
		}
	}
}

func stixEndpoint(id string) bool {
	switch stixKind(id) {
	case "relationship", "sighting", "bundle", "marking-definition", "language-content":
		return false
	}
	return caso.ValidSTIXID(id)
}

func validObservation(observation *caso.STIXObservation) bool {
	if observation == nil || observation.Count < 1 || observation.Count > 999999999 {
		return false
	}
	first, firstErr := time.Parse(time.RFC3339Nano, observation.First)
	last, lastErr := time.Parse(time.RFC3339Nano, observation.Last)
	return firstErr == nil && lastErr == nil && !last.Before(first)
}

func validObservedRefs(refs []caso.STIXRef) bool {
	for _, ref := range refs {
		if ref.Role != "observado" || !caso.ValidSTIXID(ref.ID) {
			return false
		}
		switch stixKind(ref.ID) {
		case "artifact", "autonomous-system", "directory", "domain-name", "email-addr", "email-message", "file",
			"ipv4-addr", "ipv6-addr", "mac-addr", "mutex", "network-traffic", "process", "software", "url", "user-account",
			"windows-registry-key", "x509-certificate", "relationship", "sighting":
		default:
			return false
		}
	}
	return len(refs) > 0
}

func canResolveSTIX(source, target string) bool {
	switch source {
	case "domain-name":
		return target == "domain-name" || target == "ipv4-addr" || target == "ipv6-addr"
	case "ipv4-addr", "ipv6-addr":
		return target == "mac-addr"
	}
	return false
}

func (build *stixBuilder) resolve(id, scope string) string {
	options := build.targets[id]
	var same, unique string
	for _, item := range options {
		if item.scope == scope {
			if same != "" && same != item.id {
				return id
			}
			same = item.id
		}
		if unique == "" {
			unique = item.id
		} else if unique != item.id {
			unique = id
		}
	}
	if same != "" {
		return same
	}
	if unique != "" {
		return unique
	}
	return id
}

func (build *stixBuilder) sco(entry *exchangeEntry) string {
	canonical, _ := json.Marshal(struct {
		Hashes map[string]string `json:"hashes,omitempty"`
		Value  string            `json:"value,omitempty"`
	}{entry.Hashes, entry.Value})
	namespace := []byte{0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7}
	sum := sha1.Sum(append(namespace, canonical...))
	entry.ID = formatSTIXID(entry.Type, sum[:16], 5)
	if _, known := build.scos[entry.ID]; !known {
		entry.Version = "2.1"
		build.scos[entry.ID] = entry
		build.entries = append(build.entries, entry)
	}
	return entry.ID
}

func newSTIXID(kind string) string {
	var id [16]byte
	rand.Read(id[:])
	return formatSTIXID(kind, id[:], 4)
}

func formatSTIXID(kind string, id []byte, version byte) string {
	id[6] = id[6]&0x0f | version<<4
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%s--%x-%x-%x-%x-%x", kind, id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func stixKind(id string) string {
	kind, _, _ := strings.Cut(id, "--")
	return kind
}

func stixSCOType(kind string) string {
	switch kind {
	case "dominio":
		return "domain-name"
	case "ipv4", "ipv6":
		return kind + "-addr"
	}
	return ""
}

func stixHashName(kind string) string {
	switch kind {
	case "sha256":
		return "SHA-256"
	case "sha1":
		return "SHA-1"
	case "md5":
		return "MD5"
	}
	return ""
}

func refByRole(refs []caso.STIXRef, role string) string {
	for _, ref := range refs {
		if ref.Role == role {
			return ref.ID
		}
	}
	return ""
}

func appendDistinct(values []string, candidate string) []string {
	if !slices.Contains(values, candidate) {
		return append(values, candidate)
	}
	return values
}

func evidenceOrigin(record caso.Record, stixID string) caso.STIXOrigin {
	description := "Tipo · " + clip(record.Kind, 60)
	if source := clip(record.SourceID, 160); source != "" {
		description += " | Posición · " + source
	}
	if sha := digest(record.SHA256); sha != "" {
		description += " | SHA-256 · " + sha
	}
	if stixID != "" {
		description += " | Objeto STIX · " + stixID
	}
	return caso.STIXOrigin{SourceName: "PAVAROTTI", ExternalID: record.ID + "@" + strconv.Itoa(record.Revision), Description: clip(description, 512)}
}

func networkPrefixes(network assetNetwork) []netip.Prefix {
	if network.prefix.IsValid() {
		return []netip.Prefix{network.prefix}
	}
	var result []netip.Prefix
	for first := network.start; first.IsValid() && first.Compare(network.end) <= 0; {
		best := netip.PrefixFrom(first, first.BitLen())
		last := first
		for bits := best.Bits() - 1; bits >= 0; bits-- {
			candidate := netip.PrefixFrom(first, bits).Masked()
			if candidate.Addr() != first {
				break
			}
			end := prefixLast(candidate)
			if end.Compare(network.end) > 0 {
				break
			}
			best, last = candidate, end
		}
		result = append(result, best)
		first = last.Next()
	}
	return result
}

func prefixLast(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Addr().As16()
	for bit := 128 - prefix.Addr().BitLen() + prefix.Bits(); bit < 128; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	if prefix.Addr().Is4() {
		return netip.AddrFrom16(bytes).Unmap()
	}
	return netip.AddrFrom16(bytes)
}
