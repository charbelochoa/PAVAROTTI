package caso

import (
	"encoding/json"
	"strings"
)

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

type DependencyInventory struct {
	Ecosystem string       `json:"ecosystem"`
	Manifest  string       `json:"manifest"`
	Project   string       `json:"project,omitempty"`
	Entries   []Dependency `json:"entries"`
	Skipped   int          `json:"skipped,omitempty"`
}

type Dependency struct {
	Name        string       `json:"name"`
	Version     string       `json:"version,omitempty"`
	Scope       string       `json:"scope"`
	Line        int          `json:"line,omitempty"`
	Location    string       `json:"location,omitempty"`
	InstalledAs string       `json:"installed_as,omitempty"`
	Integrity   string       `json:"integrity,omitempty"`
	Replacement *Replacement `json:"replacement,omitempty"`
}

type Replacement struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Local   bool   `json:"local,omitempty"`
	Line    int    `json:"line"`
}

func (record Record) MatchesDependency(term string) bool {
	for field := range record.dependencySearchFields {
		if strings.Contains(strings.ToLower(field), term) {
			return true
		}
	}
	return false
}

func (record Record) dependencySearchFields(yield func(string) bool) {
	if record.Dependencies == nil {
		return
	}
	for _, entry := range record.Dependencies.Entries {
		if !yield(entry.Name) || !yield(entry.Version) || !yield(entry.InstalledAs) {
			return
		}
		if entry.Replacement != nil && (!yield(entry.Replacement.Name) || !yield(entry.Replacement.Version)) {
			return
		}
	}
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
