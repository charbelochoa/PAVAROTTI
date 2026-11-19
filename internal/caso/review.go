package caso

import "encoding/json"

type CodeReview struct {
	Package string    `json:"package"`
	Imports []string  `json:"imports"`
	Signals []Finding `json:"signals"`
	Engine  string    `json:"engine,omitempty"`
	Total   int       `json:"total,omitempty"`
}

type Finding struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Rule   string `json:"rule"`
	Review string `json:"review"`
}

func (record Record) StaticReview() *CodeReview {
	if record.Kind != "código" {
		return nil
	}
	if record.Review != nil {
		return record.Review
	}
	if len(record.Details) > 2<<20 {
		return nil
	}
	var review CodeReview
	if json.Unmarshal([]byte(record.Details), &review) != nil || review.Package == "" {
		return nil
	}
	review.Engine, review.Total = "go-ast-1", len(review.Signals)
	return &review
}
