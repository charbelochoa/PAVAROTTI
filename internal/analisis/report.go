package analisis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

const (
	RecordLimit    = 10_000
	groupLimit     = 100
	referenceLimit = 5
	timelineLimit  = 50
)

var ErrLimit = errors.New("el informe admite hasta 10000 registros por ejecución")

type Report struct {
	Records   int           `json:"records"`
	Assets    []Group       `json:"assets"`
	Hashes    []Group       `json:"hashes"`
	Signals   []Group       `json:"signals"`
	Responses []Group       `json:"responses"`
	Timeline  []Evidence    `json:"timeline"`
	Agents    []AgentResult `json:"agents"`
}

type Group struct {
	Value    string     `json:"value"`
	Scope    string     `json:"scope,omitempty"`
	Count    int        `json:"count"`
	Evidence []Evidence `json:"evidence"`
}

type Evidence struct {
	Kind     string `json:"kind"`
	Time     string `json:"time"`
	Title    string `json:"title"`
	SourceID string `json:"source_id,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type AgentResult struct {
	Name     string `json:"name"`
	Reviewed int    `json:"reviewed"`
	Matched  int    `json:"matched"`
	Shown    int    `json:"shown"`
}

type observation struct {
	record caso.Record
	ref    Evidence
	date   time.Time
}

type result struct {
	apply func(*Report)
	err   error
}

func Analyze(ctx context.Context, records []caso.Record) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if len(records) > RecordLimit {
		return Report{}, ErrLimit
	}
	observations := make([]observation, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		date, _ := time.Parse(time.RFC3339Nano, record.Time)
		observations = append(observations, observation{record: record, date: date, ref: Evidence{
			Kind: clip(record.Kind, 64), Time: clip(record.Time, 48), Title: clip(record.Title, 160),
			SourceID: clip(record.SourceID, 160), SHA256: digest(record.SHA256),
		}})
	}
	slices.SortStableFunc(observations, func(a, b observation) int {
		return b.date.Compare(a.date)
	})
	agents := []func(context.Context, []observation) result{inventory, httpSignals, chronology}
	tasks := make([]chan result, len(agents))
	for index, agent := range agents {
		tasks[index] = make(chan result, 1)
		go func(output chan<- result) { output <- agent(ctx, observations) }(tasks[index])
	}
	report := Report{Records: len(records)}
	for _, task := range tasks {
		select {
		case <-ctx.Done():
			return Report{}, ctx.Err()
		case output := <-task:
			if output.err != nil {
				return Report{}, output.err
			}
			output.apply(&report)
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (r Report) Text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Análisis del expediente\nRegistros revisados  %d\n", r.Records)
	for _, agent := range r.Agents {
		fmt.Fprintf(&out, "%s  %d coincidencias, %d mostradas\n", agent.Name, agent.Matched, agent.Shown)
	}
	for _, section := range []struct {
		name   string
		groups []Group
	}{{"Activos observados", r.Assets}, {"Huellas de evidencia", r.Hashes}, {"Respuestas HTTP", r.Responses}, {"Señales HTTP", r.Signals}} {
		if len(section.groups) == 0 {
			continue
		}
		fmt.Fprintf(&out, "\n%s\n", section.name)
		for _, group := range section.groups {
			scope := ""
			if group.Scope != "" {
				scope = " · " + group.Scope
			}
			fmt.Fprintf(&out, "%s%s  (%d)\n", group.Value, scope, group.Count)
			for _, ref := range group.Evidence {
				fmt.Fprintf(&out, "  %s\n", ref.text())
			}
		}
	}
	if len(r.Timeline) > 0 {
		out.WriteString("\nCronología de registro\n")
		for _, ref := range r.Timeline {
			fmt.Fprintf(&out, "%s\n", ref.text())
		}
	}
	return out.String()
}

func (e Evidence) text() string {
	fields := []string{e.Time, e.Kind, e.Title}
	for _, value := range []string{e.SourceID, e.SHA256} {
		if value != "" {
			fields = append(fields, value)
		}
	}
	return strings.Join(fields, " · ")
}
