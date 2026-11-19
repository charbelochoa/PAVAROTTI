package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func terminalAnalyze(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("analizar", "analizar [--json]", stderr)
	asJSON := flags.Bool("json", false, "emite un informe estructurado")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usa pavarotti analizar --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	records, err := store.Records()
	if err != nil {
		return err
	}
	report, err := analisis.Analyze(context.Background(), records)
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	_, err = io.WriteString(stdout, terminalMultiline(report.Text()))
	return err
}

func terminalEdit(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("editar", "editar --id <id> --revision <n> [--titulo <título>] [--origen <referencia>] [--texto <nota>]", stderr)
	id := flags.String("id", "", "identificador de la nota")
	revision := flags.Int("revision", 0, "revisión actual de la nota")
	title := flags.String("titulo", "", "nuevo título")
	source := flags.String("origen", "", "nueva referencia, usa una cadena vacía para quitarla")
	details := flags.String("texto", "", "nuevo texto")
	if err := flags.Parse(args); err != nil {
		return err
	}
	fields := map[string]bool{}
	flags.Visit(func(field *flag.Flag) { fields[field.Name] = true })
	if flags.NArg() != 0 || *id == "" || *revision < 1 || (!fields["titulo"] && !fields["texto"] && !fields["origen"]) {
		return errors.New("indica el ID, la revisión y al menos un campo para actualizar")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	records, err := store.Records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.ID != *id {
			continue
		}
		if !fields["titulo"] {
			*title = record.Title
		}
		if !fields["origen"] {
			*source = record.Source
		}
		if !fields["texto"] {
			*details = record.Details
		}
		updated, err := store.Edit(*id, *revision, *title, *source, *details)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "Nota guardada · %s · revisión %d\n", terminalText(updated.ID), updated.Revision)
		return err
	}
	return caso.ErrNotFound
}

func terminalHistory(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("historial", "historial --id <id> [--json]", stderr)
	id := flags.String("id", "", "identificador de la nota")
	asJSON := flags.Bool("json", false, "emite las versiones como JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *id == "" {
		return errors.New("indica el ID de una nota")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	history, err := store.History(*id)
	if err != nil {
		return err
	}
	if *asJSON {
		return encodeRecords(stdout, "json", history)
	}
	if len(history) == 0 {
		_, err := fmt.Fprintln(stdout, "Sin revisiones previas.")
		return err
	}
	for _, record := range history {
		if _, err := fmt.Fprintf(stdout, "Revisión %d · %s\n%s\n", record.Revision,
			terminalText(record.Title), terminalMultiline(record.Details)); err != nil {
			return err
		}
		if record.Source != "" {
			if _, err := fmt.Fprintln(stdout, terminalText(record.Source)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
	}
	return nil
}

func terminalMultiline(text string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.In(r, unicode.Cf)) {
			return ' '
		}
		return r
	}, text)
}
