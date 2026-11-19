package analisis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"pavarotti/internal/caso"
)

const (
	AgentVersion      = "3"
	legacyAgent       = "1"
	networkAgent      = "2"
	SnapshotByteLimit = 32 << 20
)

var ErrSnapshotBytes = errors.New("los datos de entrada del análisis superan 32 MiB")

type Snapshot struct {
	Records      []caso.Record `json:"records"`
	Fingerprint  string        `json:"sha256"`
	AgentVersion string        `json:"agent_version"`
}

func Prepare(ctx context.Context, store *caso.Store) (Snapshot, error) {
	snapshot := Snapshot{Records: make([]caso.Record, 0), AgentVersion: AgentVersion}
	size := 0
	err := store.Walk(ctx, func(record caso.Record) error {
		if len(snapshot.Records) == RecordLimit {
			return ErrLimit
		}
		evidence := analysisRecord(record)
		data, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		size += len(data) + 1
		if size > SnapshotByteLimit {
			return ErrSnapshotBytes
		}
		snapshot.Records = append(snapshot.Records, evidence)
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	slices.SortFunc(snapshot.Records, func(a, b caso.Record) int { return strings.Compare(a.ID, b.ID) })
	fingerprint, err := snapshot.checksum(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Fingerprint = fingerprint
	return snapshot, nil
}

func (snapshot Snapshot) checksum(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(snapshot.Records) > RecordLimit {
		return "", ErrLimit
	}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	if err := encoder.Encode(snapshot.AgentVersion); err != nil {
		return "", err
	}
	for _, record := range snapshot.Records {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := encoder.Encode(record); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func analysisRecord(base caso.Record) caso.Record {
	record := caso.Record{
		ID: base.ID, Revision: base.Revision, UpdatedAt: clip(base.UpdatedAt, 48),
		Kind: clip(base.Kind, 64), Time: clip(base.Time, 48), Title: clip(base.Title, 160),
		SourceID: clip(base.SourceID, 160), SHA256: digest(base.SHA256),
		Network: recordNetwork(base).value,
	}
	hosts := observedHosts(base.Source)
	if base.Traffic != nil {
		record.Traffic = &caso.Traffic{Status: base.Traffic.Status}
		if host := networkHost(base.Source); host != "" {
			hosts = []string{host}
		}
	}
	for i, host := range hosts {
		if strings.ContainsRune(host, ':') {
			host = "[" + host + "]"
		}
		hosts[i] = "http://" + host
	}
	record.Source = strings.Join(hosts, ",")
	if base.Indicator != nil {
		record.Indicator = &caso.Indicator{Type: clip(base.Indicator.Type, 32), Value: clip(base.Indicator.Value, 253)}
	}
	for _, signal := range base.Signals[:min(len(base.Signals), 32)] {
		record.Signals = append(record.Signals, clip(signal, 160))
	}
	projectAudit(&record, base)
	return record
}

func (snapshot Snapshot) Analyze(ctx context.Context) (Report, error) {
	if !supportedAgent(snapshot.AgentVersion) {
		return Report{}, errors.New("versión de agentes desconocida")
	}
	report, err := analyze(ctx, snapshot.Records, snapshot.AgentVersion)
	if err != nil {
		return Report{}, err
	}
	report.InputSHA256 = snapshot.Fingerprint
	report.AgentVersion = snapshot.AgentVersion
	return report, nil
}

func supportedAgent(version string) bool {
	return version == AgentVersion || version == networkAgent || version == legacyAgent
}
