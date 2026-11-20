package analisis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"pavarotti/internal/caso"
)

const AssetCoverageSchema = "pavarotti.asset-coverage.v1"

type AssetCoverageCriteria struct {
	AssetKey
	From string `json:"from"`
	To   string `json:"to"`
}

type AssetCoverageReport struct {
	Schema         string                `json:"schema"`
	InputSHA256    string                `json:"input_sha256"`
	Criteria       AssetCoverageCriteria `json:"criteria"`
	Direct         int                   `json:"direct"`
	Indicators     int                   `json:"indicators"`
	Coverage       int                   `json:"coverage"`
	Addresses      int                   `json:"addresses"`
	Observations   int                   `json:"observations"`
	Sources        []AssetReference      `json:"sources"`
	Members        []NetworkObservation  `json:"members"`
	OmittedSources int                   `json:"omitted_sources"`
	OmittedMembers int                   `json:"omitted_members"`
}

func CoverAsset(ctx context.Context, store *caso.Store, criteria AssetCoverageCriteria) (AssetCoverageReport, error) {
	key, valid := caso.NormalizeAsset(criteria.AssetKey)
	if !valid {
		return AssetCoverageReport{}, ErrAssetQuery
	}
	period, err := parseUTCPeriod(criteria.From, criteria.To)
	if err != nil {
		return AssetCoverageReport{}, fmt.Errorf("%w: %w", ErrAssetQuery, err)
	}
	criteria.AssetKey = key
	inputs, err := collectAssetInput(ctx, store, key, &period, true)
	if err != nil {
		return AssetCoverageReport{}, err
	}
	report := AssetCoverageReport{Schema: AssetCoverageSchema, Criteria: criteria, Sources: []AssetReference{}}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	if err := encoder.Encode(report.Schema); err != nil {
		return AssetCoverageReport{}, err
	}
	if err := encoder.Encode(criteria); err != nil {
		return AssetCoverageReport{}, err
	}
	for _, in := range inputs {
		if err := ctx.Err(); err != nil {
			return AssetCoverageReport{}, err
		}
		if err := encoder.Encode(in); err != nil {
			return AssetCoverageReport{}, err
		}
		switch in.Reference.Role {
		case "":
			continue
		case "cobertura":
			report.Coverage++
		default:
			report.Direct++
			if in.Reference.Role == "indicador" {
				report.Indicators++
			}
		}
		if len(report.Sources) < groupLimit {
			report.Sources = append(report.Sources, in.Reference)
		}
	}
	rows, observations := networkObservationRows(inputs)
	report.Addresses, report.Observations = len(rows), observations
	report.Members = rows[:min(len(rows), groupLimit)]
	report.OmittedSources = report.Direct + report.Coverage - len(report.Sources)
	report.OmittedMembers = len(rows) - len(report.Members)
	report.InputSHA256 = hex.EncodeToString(hash.Sum(nil))
	return report, ctx.Err()
}
