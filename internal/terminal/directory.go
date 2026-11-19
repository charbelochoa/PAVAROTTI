package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"pavarotti/internal/ingesta"
)

func terminalDirectory(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("revisar", "revisar [--json] <directorio>", stderr)
	asJSON := flags.Bool("json", false, "emite los resultados por archivo en JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("elige un directorio local para la revisión")
	}
	ctx := context.Background()
	review, err := ingesta.LoadDirectory(ctx, flags.Arg(0))
	if err != nil {
		return err
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	result, saveErr := review.Save(ctx, store)
	if saveErr != nil && result.Files == nil {
		return saveErr
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return errors.Join(saveErr, encoder.Encode(result))
	}
	for _, file := range result.Files {
		if _, err := fmt.Fprintf(stdout, "%s · %s", file.Status, terminalText(file.Path)); err != nil {
			return errors.Join(saveErr, err)
		}
		if file.Reason != "" {
			if _, err := fmt.Fprintf(stdout, " · %s", terminalText(file.Reason)); err != nil {
				return errors.Join(saveErr, err)
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return errors.Join(saveErr, err)
		}
	}
	_, err = fmt.Fprintln(stdout, result.Message())
	return errors.Join(saveErr, err)
}
