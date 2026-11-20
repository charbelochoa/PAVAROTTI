package analisis

import (
	"cmp"
	"context"
	"errors"
	"io"
	"slices"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinaryReferenceComparisonSchema = "pavarotti.binary-reference-comparison.v1"

var ErrBinaryReferenceComparison = errors.New("elige dos informes del mismo binario, imagen y destino")

type BinaryReferenceSide struct {
	RecordID         string `json:"record_id"`
	Revision         int    `json:"revision"`
	InspectionSHA256 string `json:"inspection_sha256"`
	ReportSHA256     string `json:"report_sha256"`
	Count            int    `json:"count"`
}

type BinaryReferenceChange struct {
	State       string                   `json:"state"`
	Instruction triaje.Instruction       `json:"instruction"`
	Baseline    *BinaryReferenceLocation `json:"baseline,omitempty"`
	Current     *BinaryReferenceLocation `json:"current,omitempty"`
}

type BinaryReferenceComparison struct {
	Schema             string                  `json:"schema"`
	SHA256             string                  `json:"sha256"`
	Image              int                     `json:"image"`
	Architecture       string                  `json:"architecture"`
	DestinationAddress string                  `json:"destination_address"`
	DestinationOffset  string                  `json:"destination_offset"`
	Baseline           BinaryReferenceSide     `json:"baseline"`
	Current            BinaryReferenceSide     `json:"current"`
	Shared             int                     `json:"shared"`
	Added              int                     `json:"added"`
	Absent             int                     `json:"absent"`
	Rows               []BinaryReferenceChange `json:"rows"`
}

func CompareBinaryReferences(ctx context.Context, store *caso.Store, baseline, current BinaryReferenceReport, source io.Reader) (BinaryReferenceComparison, error) {
	for _, report := range []BinaryReferenceReport{baseline, current} {
		if err := validateBinaryReferenceReport(report, true); err != nil {
			return BinaryReferenceComparison{}, err
		}
	}
	if baseline.SHA256 != current.SHA256 || baseline.Image != current.Image ||
		baseline.Destination.Address != current.Destination.Address || baseline.Destination.Offset != current.Destination.Offset {
		return BinaryReferenceComparison{}, ErrBinaryReferenceComparison
	}
	evidence, err := openBinaryWindowEvidence(ctx, store, baseline.RecordID, baseline.Revision, source)
	if err != nil {
		return BinaryReferenceComparison{}, err
	}
	prior, err := evidence.reviewReferences(ctx, baseline, true, nil)
	if err != nil {
		return BinaryReferenceComparison{}, err
	}
	if baseline.RecordID != current.RecordID || baseline.Revision != current.Revision {
		other, err := openBinaryWindowEvidence(ctx, store, current.RecordID, current.Revision, nil)
		if err != nil {
			return BinaryReferenceComparison{}, err
		}
		if other.record.SHA256 != baseline.SHA256 || other.inspection.Size != len(evidence.data) {
			return BinaryReferenceComparison{}, ErrBinaryReferenceReport
		}
		other.data, other.images = evidence.data, evidence.images
		evidence = other
	}
	later, err := evidence.reviewReferences(ctx, current, true, &prior)
	if err != nil {
		return BinaryReferenceComparison{}, err
	}
	return compareVerifiedReferences(ctx, prior, later)
}

func compareVerifiedReferences(ctx context.Context, baseline, current BinaryReferenceReview) (BinaryReferenceComparison, error) {
	side := func(report BinaryReferenceReport) BinaryReferenceSide {
		return BinaryReferenceSide{RecordID: report.RecordID, Revision: report.Revision,
			InspectionSHA256: report.InspectionSHA256, ReportSHA256: report.ReportSHA256, Count: len(report.Origins)}
	}
	comparison := BinaryReferenceComparison{Schema: BinaryReferenceComparisonSchema, SHA256: current.Report.SHA256,
		Image: current.Report.Image, Architecture: current.Destination.Window.Architecture, DestinationAddress: current.Report.Destination.Address,
		DestinationOffset: current.Report.Destination.Offset, Baseline: side(baseline.Report), Current: side(current.Report)}
	rows := make(map[[2]string]BinaryReferenceChange, len(baseline.Origins)+len(current.Origins))
	for index, instruction := range baseline.Origins {
		if err := ctx.Err(); err != nil {
			return BinaryReferenceComparison{}, err
		}
		rows[[2]string{instruction.Address, instruction.Offset}] = BinaryReferenceChange{State: "ausente", Instruction: instruction, Baseline: &baseline.Report.Origins[index]}
	}
	for index, instruction := range current.Origins {
		if err := ctx.Err(); err != nil {
			return BinaryReferenceComparison{}, err
		}
		key := [2]string{instruction.Address, instruction.Offset}
		row, found := rows[key]
		if found {
			row.State = "comun"
			comparison.Shared++
		} else {
			row.State = "agregado"
			comparison.Added++
		}
		row.Instruction, row.Current = instruction, &current.Report.Origins[index]
		rows[key] = row
	}
	comparison.Absent = len(baseline.Origins) - comparison.Shared
	comparison.Rows = make([]BinaryReferenceChange, 0, len(rows))
	for _, row := range rows {
		comparison.Rows = append(comparison.Rows, row)
	}
	slices.SortFunc(comparison.Rows, func(a, b BinaryReferenceChange) int {
		x, _ := triaje.ParseBinaryHex(a.Instruction.Address)
		y, _ := triaje.ParseBinaryHex(b.Instruction.Address)
		if order := cmp.Compare(x, y); order != 0 {
			return order
		}
		x, _ = triaje.ParseBinaryHex(a.Instruction.Offset)
		y, _ = triaje.ParseBinaryHex(b.Instruction.Offset)
		return cmp.Compare(x, y)
	})
	if err := ctx.Err(); err != nil {
		return BinaryReferenceComparison{}, err
	}
	return comparison, nil
}
