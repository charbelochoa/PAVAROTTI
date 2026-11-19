package trafico

import (
	"fmt"
	"math/bits"
	"mime"
	"net/http"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

func Observe(origin, method string, status int, elapsed time.Duration, headers http.Header) caso.Record {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH":
	default:
		method = "OTRO"
	}
	media, _, _ := mime.ParseMediaType(headers.Get("Content-Type"))
	millis := max(int64(0), elapsed.Milliseconds())
	bucket := int64(0)
	if millis > 0 {
		bucket = int64(1) << bits.Len64(uint64(millis))
	}
	entry := caso.Record{
		Kind: "tráfico", Time: caso.Now(), Title: fmt.Sprintf("%s %d", method, status), Source: origin,
		Traffic: &caso.Traffic{Method: method, Status: status, Type: media, Millis: millis, Bucket: bucket},
	}
	if status >= 200 && status < 300 && status != 204 && method != "HEAD" {
		if media == "" {
			entry.Signals = append(entry.Signals, "Tipo de contenido ausente o inválido")
		}
		if (media == "text/html" || media == "application/xhtml+xml") &&
			!strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff") {
			entry.Signals = append(entry.Signals, "HTML sin X-Content-Type-Options: nosniff")
		}
	}
	if strings.HasPrefix(origin, "https://") && headers.Get("Strict-Transport-Security") == "" && status > 0 {
		entry.Signals = append(entry.Signals, "HTTPS sin cabecera HSTS")
	}
	return entry
}

func ImportHAR(input []byte) ([]caso.Record, error) {
	items, err := caso.HAR(input)
	if err != nil {
		return nil, err
	}
	records := make([]caso.Record, 0, len(items))
	hash := caso.Hash(input)
	for index, item := range items {
		origin := caso.Origin(item.Req.URL)
		if origin == "" || item.Resp.Status < 100 || item.Resp.Status > 599 {
			continue
		}
		headers := make(http.Header)
		for _, field := range item.Resp.Headers {
			switch strings.ToLower(field.Name) {
			case "content-type", "x-content-type-options", "strict-transport-security":
				headers.Add(field.Name, field.Value)
			}
		}
		elapsed := time.Duration(min(max(item.Time, 0), 86_400_000) * float64(time.Millisecond))
		entry := Observe(origin, item.Req.Method, item.Resp.Status, elapsed, headers)
		if started, err := time.Parse(time.RFC3339Nano, item.StartedDateTime); err == nil {
			entry.Time = started.UTC().Format(time.RFC3339Nano)
		}
		entry.Kind, entry.SHA256, entry.SourceID = "archivo HAR", hash, fmt.Sprint(index+1)
		records = append(records, entry)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("el HAR no contiene respuestas HTTP completas")
	}
	return records, nil
}
