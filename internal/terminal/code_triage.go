package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"pavarotti/internal/caso"
)

func terminalCodeTriage(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("triaje", "triaje --id <registro> [--regla <regla> --linea N --columna N] [--revision N --estado <estado> --justificacion <texto>]", stderr)
	id := flags.String("id", "", "identificador de la evidencia")
	var key caso.FindingKey
	flags.StringVar(&key.Rule, "regla", "", "regla de la señal")
	flags.IntVar(&key.Line, "linea", 0, "línea física")
	flags.IntVar(&key.Column, "columna", 0, "columna física")
	revision := flags.Int("revision", -1, "revisión actual de la clasificación, 0 si es nueva")
	status := flags.String("estado", "", "pendiente, confirmada o descartada")
	reason := flags.String("justificacion", "", "motivo de la decisión")
	if err := flags.Parse(args); err != nil {
		return err
	}
	specific := key != (caso.FindingKey{})
	if flags.NArg() != 0 || *id == "" || (specific && (key.Rule == "" || key.Line < 1 || key.Column < 1)) ||
		(*status != "" && (!specific || *revision < 0)) || (*status == "" && (*revision != -1 || *reason != "")) {
		return errors.New("usa pavarotti triaje --help")
	}
	ctx := context.Background()
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if *status != "" {
		entry, err := store.ClassifyCode(ctx, *id, key, *revision, *status, *reason)
		if err != nil {
			return err
		}
		return encoder.Encode(entry)
	}
	var results []caso.CodeDisposition
	if specific {
		results, err = store.CodeHistory(ctx, *id, key)
	} else {
		results, err = store.CodeClassifications(ctx, *id)
	}
	if err != nil {
		return err
	}
	return encoder.Encode(results)
}
