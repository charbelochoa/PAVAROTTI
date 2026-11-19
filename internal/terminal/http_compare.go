package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"pavarotti/internal/analisis"
)

func terminalHTTPComparison(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("comparar-http", "comparar-http --desde-a AAAA-MM-DD --hasta-a AAAA-MM-DD --desde-b AAAA-MM-DD --hasta-b AAAA-MM-DD [opciones]", stderr)
	var criteria analisis.HTTPCompareCriteria
	addWindow := func(window *analisis.HTTPWindow, suffix, label string) {
		flags.StringVar(&window.Origin, "origen-"+suffix, "", "origen HTTP(S) del periodo "+label)
		flags.StringVar(&window.Capture, "captura-"+suffix, "", "har o proxy para el periodo "+label)
		flags.StringVar(&window.From, "desde-"+suffix, "", "fecha UTC inicial del periodo "+label)
		flags.StringVar(&window.To, "hasta-"+suffix, "", "fecha UTC final inclusiva del periodo "+label)
	}
	addWindow(&criteria.Baseline, "a", "A")
	addWindow(&criteria.Current, "b", "B")
	output := flags.String("salida", "", "ruta nueva para el informe JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usa pavarotti comparar-http --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	report, err := analisis.CompareHTTP(context.Background(), store, criteria)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	})
}
