package analisis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

const (
	HTTPComparisonSchema      = "pavarotti.http-comparison.v1"
	HTTPComparisonWideSchema  = "pavarotti.http-comparison.v2"
	HTTPComparisonRecordLimit = 50_000
)

var (
	ErrHTTPComparisonCriteria = errors.New("criterios de comparación HTTP inválidos")
	ErrHTTPComparisonLimit    = errors.New("la comparación HTTP admite hasta 50000 observaciones distintas entre ambos periodos")
)

type HTTPCompareCriteria struct {
	Baseline HTTPWindow `json:"baseline"`
	Current  HTTPWindow `json:"current"`
}

type HTTPWindow struct {
	Origin  string `json:"origin"`
	Capture string `json:"capture"`
	From    string `json:"from"`
	To      string `json:"to"`
}

type HTTPComparison struct {
	Schema      string              `json:"schema"`
	InputSHA256 string              `json:"input_sha256"`
	Criteria    HTTPCompareCriteria `json:"criteria"`
	Baseline    HTTPWindowStats     `json:"baseline"`
	Current     HTTPWindowStats     `json:"current"`
	Rows        []HTTPCompareRow    `json:"rows"`
	OmittedRows int                 `json:"omitted_rows"`
}

type HTTPWindowStats struct {
	Observations      int `json:"observations"`
	Responses         int `json:"responses"`
	TransportFailures int `json:"transport_failures"`
	Assessed          int `json:"assessed"`
}

type HTTPCompareRow struct {
	Kind     string    `json:"kind"`
	Code     string    `json:"code"`
	Label    string    `json:"label"`
	Baseline HTTPTally `json:"baseline"`
	Current  HTTPTally `json:"current"`
}

type HTTPTally struct {
	Count    int                      `json:"count"`
	Evidence []HTTPComparisonEvidence `json:"evidence,omitempty"`
}

type HTTPComparisonEvidence struct {
	Evidence
	Origin string `json:"origin,omitempty"`
}

type httpWindowFilter struct {
	HTTPWindow
	caso.EvidencePeriod
}

type httpRowKey struct {
	Kind string `json:"kind"`
	Code string `json:"code"`
}

type httpMetric struct {
	httpRowKey
	Label string `json:"label"`
}

type httpComparisonInput struct {
	Ref      HTTPComparisonEvidence `json:"ref"`
	Baseline bool                   `json:"baseline"`
	Current  bool                   `json:"current"`
	Assessed bool                   `json:"assessed"`
	Category httpMetric             `json:"category"`
	Signals  []httpMetric           `json:"signals,omitempty"`
}

func CompareHTTP(ctx context.Context, store *caso.Store, criteria HTTPCompareCriteria) (HTTPComparison, error) {
	a, err := normalizeHTTPWindow(criteria.Baseline)
	if err != nil {
		return HTTPComparison{}, fmt.Errorf("%w en el periodo A: %w", ErrHTTPComparisonCriteria, err)
	}
	b, err := normalizeHTTPWindow(criteria.Current)
	if err != nil {
		return HTTPComparison{}, fmt.Errorf("%w en el periodo B: %w", ErrHTTPComparisonCriteria, err)
	}
	criteria = HTTPCompareCriteria{Baseline: a.HTTPWindow, Current: b.HTTPWindow}
	comparison := httpComparisonAccumulator{groups: make(map[httpRowKey]*httpComparisonGroup)}
	filter := caso.EvidenceFilter{HTTP: true, Periods: []caso.EvidencePeriod{a.EvidencePeriod, b.EvidencePeriod}}
	err = store.WalkFiltered(ctx, filter, func(record caso.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		stamp, err := time.Parse(time.RFC3339Nano, record.Time)
		if err != nil {
			return nil
		}
		origin := normalizeHTTPOrigin(record.Source)
		inA, inB := a.matches(stamp, origin, record.Kind), b.matches(stamp, origin, record.Kind)
		if !inA && !inB {
			return nil
		}
		if len(comparison.sources) == HTTPComparisonRecordLimit {
			return ErrHTTPComparisonLimit
		}
		return comparison.add(ctx, stamp, compareHTTPInput(record, origin, inA, inB))
	})
	if err != nil {
		return HTTPComparison{}, err
	}
	return comparison.finish(ctx, criteria)
}

func normalizeHTTPWindow(window HTTPWindow) (httpWindowFilter, error) {
	window.Origin = strings.TrimSpace(window.Origin)
	if window.Origin != "" {
		window.Origin = normalizeHTTPOrigin(window.Origin)
		if window.Origin == "" {
			return httpWindowFilter{}, errors.New("indica un origen HTTP(S) con esquema y host, sin ruta ni parámetros")
		}
	}
	switch strings.ToLower(strings.TrimSpace(window.Capture)) {
	case "":
		window.Capture = ""
	case "har", "archivo har":
		window.Capture = "archivo HAR"
	case "proxy", "trafico", "tráfico":
		window.Capture = "tráfico"
	default:
		return httpWindowFilter{}, errors.New("elige HAR, proxy o todas las capturas")
	}
	period, err := parseUTCPeriod(window.From, window.To)
	if err != nil {
		return httpWindowFilter{}, err
	}
	return httpWindowFilter{HTTPWindow: window, EvidencePeriod: period}, nil
}

func (w httpWindowFilter) matches(stamp time.Time, origin, kind string) bool {
	return w.Includes(stamp) &&
		(w.Origin == "" || w.Origin == origin) && (w.Capture == "" || w.Capture == kind)
}

func normalizeHTTPOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" ||
		u.RawPath != "" || (u.Path != "" && u.Path != "/") || u.ForceQuery || u.RawQuery != "" || strings.Contains(raw, "#") {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if host == "" || len(host) > 253 || strings.HasSuffix(u.Host, ":") {
		return ""
	}
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return ""
		}
		host = address.String()
	} else if strings.Contains(host, ":") {
		return ""
	} else {
		host = strings.ToLower(host)
	}
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return ""
		}
		port = strconv.FormatUint(number, 10)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return (&url.URL{Scheme: u.Scheme, Host: host}).String()
}

func compareHTTPInput(record caso.Record, origin string, inA, inB bool) httpComparisonInput {
	input := httpComparisonInput{Ref: HTTPComparisonEvidence{Evidence: reference(record), Origin: origin},
		Baseline: inA, Current: inB}
	status := record.Traffic.Status
	switch {
	case record.HTTPTransportFailure():
		input.Category = httpMetric{httpRowKey{"transport", "sin-respuesta"}, "El proxy no recibió respuesta"}
	case status >= 100 && status <= 599:
		code := strconv.Itoa(status/100) + "xx"
		input.Category = httpMetric{httpRowKey{"status", code}, "Respuestas " + code}
		input.Assessed = status >= 200 && record.HTTPRuleSet == 1
	default:
		input.Category = httpMetric{httpRowKey{"unknown", "estado-desconocido"}, "Estado HTTP desconocido"}
	}
	seen := make(map[httpRowKey]bool)
	labels := make(map[string]bool)
	for _, finding := range record.HTTPFindings {
		if !caso.ValidHTTPRule(finding.Rule) {
			continue
		}
		label := clip(finding.Label, 180)
		labels[label] = true
		key := httpRowKey{"rule", finding.Rule}
		if !seen[key] {
			input.Signals = append(input.Signals, httpMetric{key, label})
			seen[key] = true
		}
	}
	for _, signal := range record.Signals {
		label := clip(signal, 180)
		if label == "" || labels[label] || (input.Category.Kind == "transport" && signal == caso.ProxyNoResponseSignal) {
			continue
		}
		key := httpRowKey{"legacy", label}
		if !seen[key] {
			input.Signals = append(input.Signals, httpMetric{key, label})
			seen[key] = true
		}
	}
	return input
}

func (stats *HTTPWindowStats) count(input httpComparisonInput) {
	stats.Observations++
	switch input.Category.Kind {
	case "status":
		stats.Responses++
	case "transport":
		stats.TransportFailures++
	}
	if input.Assessed {
		stats.Assessed++
	}
}
