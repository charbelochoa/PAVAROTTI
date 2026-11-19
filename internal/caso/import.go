package caso

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

type exportedFinding struct {
	ID           json.RawMessage `json:"id"`
	FindingID    json.RawMessage `json:"finding_id"`
	Name         string          `json:"name"`
	Class        string          `json:"vulnclass"`
	Severity     string          `json:"severity"`
	Status       string          `json:"status"`
	Verification string          `json:"verification_status"`
	Summary      string          `json:"summary"`
	Evidence     string          `json:"evidence"`
	Report       string          `json:"report"`
	Timestamp    string          `json:"ts"`
	Assets       []struct {
		Label string `json:"label"`
	} `json:"assets"`
}

func Findings(data []byte) ([]Record, error) {
	var items []exportedFinding
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &items); err != nil || len(items) == 0 {
		return nil, errors.New("se esperaba una lista JSON con hallazgos")
	}
	hash := Hash(data)
	results := make([]Record, 0, len(items))
	timestamp := Now()
	for _, item := range items {
		id := identifier(item.FindingID)
		if id == "" {
			id = identifier(item.ID)
		}
		title := strings.TrimSpace(item.Name)
		if title == "" {
			title = strings.TrimSpace(item.Class)
		}
		if id == "" || (title == "" && strings.TrimSpace(item.Summary) == "") {
			return nil, errors.New("cada hallazgo necesita un ID y un título o resumen")
		}
		if title == "" {
			title = "Hallazgo " + id
		}
		var assets []string
		for _, asset := range item.Assets {
			if label := strings.TrimSpace(asset.Label); label != "" {
				assets = append(assets, label)
			}
		}
		details := strings.Join([]string{
			"Severidad: " + item.Severity, "Estado: " + item.Status, "Verificación declarada: " + item.Verification,
			"Fecha de origen: " + item.Timestamp, "Activos: " + strings.Join(assets, ", "),
			item.Summary, item.Evidence, item.Report,
		}, "\n")
		results = append(results, Record{Kind: "hallazgo", Time: timestamp, Title: title,
			Source: strings.Join(assets, ", "), SourceID: id, SHA256: hash, Details: strings.TrimSpace(details)})
	}
	return results, nil
}

func identifier(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

type HARItem struct {
	Time float64 `json:"time"`
	Req  struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Resp struct {
		Status  int `json:"status"`
		Headers []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
	} `json:"response"`
}

func HAR(data []byte) ([]HARItem, error) {
	var doc struct {
		Log struct {
			Entries []HARItem `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &doc); err != nil || len(doc.Log.Entries) == 0 {
		return nil, errors.New("se esperaba un HAR con transacciones HTTP")
	}
	return doc.Log.Entries, nil
}

func Origin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
