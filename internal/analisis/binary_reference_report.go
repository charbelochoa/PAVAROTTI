package analisis

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinaryReferenceSchema = "pavarotti.binary-references.v1"
const MaxBinaryReferenceReportBytes = 4 << 20
const maxBinaryReferenceOrigins = 2048 + 64*(triaje.MaxWindowInstructions+1)

var ErrBinaryReferenceReport = errors.New("el informe de referencias es inválido o no coincide con el binario verificado")

type BinaryReferenceLocation struct {
	Kind         string `json:"kind"`
	Index        int    `json:"index"`
	Path         string `json:"path,omitempty"`
	Row          int    `json:"row"`
	Address      string `json:"address"`
	Offset       string `json:"offset"`
	WindowSHA256 string `json:"window_sha256,omitempty"`
}

type BinaryReferenceReport struct {
	Schema           string                    `json:"schema"`
	RecordID         string                    `json:"record_id"`
	Revision         int                       `json:"revision"`
	SHA256           string                    `json:"sha256"`
	InspectionSHA256 string                    `json:"inspection_sha256,omitempty"`
	Image            int                       `json:"image"`
	Destination      BinaryReferenceLocation   `json:"destination"`
	Origins          []BinaryReferenceLocation `json:"origins"`
	ReportSHA256     string                    `json:"report_sha256,omitempty"`
}

type BinaryReferenceReview struct {
	Report      BinaryReferenceReport `json:"report"`
	Destination BinaryWindowReport    `json:"destination"`
	Origins     []triaje.Instruction  `json:"origins"`
}

func ReadBinaryReferenceReport(source io.Reader) (BinaryReferenceReport, error) {
	data, err := io.ReadAll(io.LimitReader(source, MaxBinaryReferenceReportBytes+1))
	if err != nil {
		return BinaryReferenceReport{}, err
	}
	var report BinaryReferenceReport
	if len(data) > MaxBinaryReferenceReportBytes || json.Unmarshal(data, &report) != nil {
		return BinaryReferenceReport{}, ErrBinaryReferenceReport
	}
	return report, nil
}

func ReviewBinaryReferences(ctx context.Context, store *caso.Store, report BinaryReferenceReport, source io.Reader, verify bool) (BinaryReferenceReview, error) {
	if err := validateBinaryReferenceReport(report, verify); err != nil {
		return BinaryReferenceReview{}, err
	}
	evidence, err := openBinaryWindowEvidence(ctx, store, report.RecordID, report.Revision, source)
	if err != nil {
		return BinaryReferenceReview{}, err
	}
	return evidence.reviewReferences(ctx, report, verify, nil)
}

func validateBinaryReferenceReport(report BinaryReferenceReport, verify bool) error {
	if report.Schema != BinaryReferenceSchema || report.RecordID == "" || report.Revision < 1 || report.Image < 0 ||
		len(report.Origins) == 0 || len(report.Origins) > maxBinaryReferenceOrigins {
		return ErrBinaryReferenceReport
	}
	if verify {
		if report.ReportSHA256 == "" || report.InspectionSHA256 == "" || report.Destination.WindowSHA256 == "" {
			return ErrBinaryReferenceReport
		}
		digest, err := binaryReferenceDigest(report)
		if err != nil || digest != report.ReportSHA256 {
			return ErrBinaryReferenceReport
		}
	}
	return nil
}

func (evidence *binaryWindowEvidence) reviewReferences(ctx context.Context, report BinaryReferenceReport, verify bool, prior *BinaryReferenceReview) (BinaryReferenceReview, error) {
	if report.SHA256 != evidence.record.SHA256 || (report.InspectionSHA256 != "" && report.InspectionSHA256 != evidence.inspectionHash) {
		return BinaryReferenceReview{}, ErrBinaryReferenceReport
	}
	report.InspectionSHA256 = evidence.inspectionHash
	report.Origins = slices.Clone(report.Origins)
	cache := make(map[BinaryWindowRequest]BinaryWindowReport)
	open := func(location *BinaryReferenceLocation) (BinaryWindowReport, triaje.Instruction, error) {
		if err := ctx.Err(); err != nil {
			return BinaryWindowReport{}, triaje.Instruction{}, err
		}
		request := BinaryWindowRequest{RecordID: report.RecordID, Revision: report.Revision, Kind: location.Kind,
			Index: location.Index, Path: location.Path}
		window, found := cache[request]
		if !found {
			var err error
			window, err = evidence.window(ctx, request)
			if errors.Is(err, ErrBinaryWindowRequest) || errors.Is(err, triaje.ErrInstructionLocation) {
				err = ErrBinaryReferenceReport
			}
			if err != nil {
				return BinaryWindowReport{}, triaje.Instruction{}, err
			}
			if len(cache) == 64 {
				clear(cache)
			}
			cache[request] = window
		}
		if window.Window.Image != report.Image || location.Row < 0 || location.Row >= len(window.Window.Instructions) ||
			((verify || location.WindowSHA256 != "") && location.WindowSHA256 != window.Citation.WindowSHA256) {
			return BinaryWindowReport{}, triaje.Instruction{}, ErrBinaryReferenceReport
		}
		instruction := window.Window.Instructions[location.Row]
		if instruction.Text == "" || instruction.Address != location.Address || instruction.Offset != location.Offset {
			return BinaryWindowReport{}, triaje.Instruction{}, ErrBinaryReferenceReport
		}
		location.WindowSHA256 = window.Citation.WindowSHA256
		return window, instruction, nil
	}
	destination, _, err := open(&report.Destination)
	if err != nil {
		return BinaryReferenceReview{}, err
	}
	image, err := evidence.image(report.Image)
	if err != nil || !image.MatchesLocation(report.Destination.Address, report.Destination.Offset) {
		return BinaryReferenceReview{}, ErrBinaryReferenceReport
	}
	var verified map[BinaryReferenceLocation]int
	if verify && prior != nil && prior.Report.RecordID == report.RecordID && prior.Report.Revision == report.Revision &&
		prior.Report.SHA256 == report.SHA256 && prior.Report.InspectionSHA256 == report.InspectionSHA256 && prior.Report.Image == report.Image &&
		prior.Report.Destination.Address == report.Destination.Address && prior.Report.Destination.Offset == report.Destination.Offset {
		verified = make(map[BinaryReferenceLocation]int, len(prior.Origins))
		for index, location := range prior.Report.Origins {
			verified[location] = index
		}
	}
	seen := make(map[[2]string]bool, len(report.Origins))
	origins := make([]triaje.Instruction, 0, len(report.Origins))
	for index := range report.Origins {
		if err := ctx.Err(); err != nil {
			return BinaryReferenceReview{}, err
		}
		var instruction triaje.Instruction
		if previous, found := verified[report.Origins[index]]; found {
			instruction = prior.Origins[previous]
		} else {
			_, instruction, err = open(&report.Origins[index])
			if err != nil {
				return BinaryReferenceReview{}, err
			}
		}
		key := [2]string{instruction.Address, instruction.Offset}
		if instruction.Target != report.Destination.Address || seen[key] {
			return BinaryReferenceReview{}, ErrBinaryReferenceReport
		}
		seen[key] = true
		origins = append(origins, instruction)
	}
	if !verify {
		report.ReportSHA256, err = binaryReferenceDigest(report)
		if err != nil {
			return BinaryReferenceReview{}, err
		}
	}
	return BinaryReferenceReview{Report: report, Destination: destination, Origins: origins}, nil
}

func binaryReferenceDigest(report BinaryReferenceReport) (string, error) {
	report.ReportSHA256 = ""
	encoded, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return caso.Hash(encoded), nil
}
