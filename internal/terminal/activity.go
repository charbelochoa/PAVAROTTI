package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

func terminalActivity(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("actividad", "actividad [--limite N] [--antes N] [--salida archivo.json]", stderr)
	limit := flags.Int("limite", 50, "número de eventos, entre 1 y 100")
	before := flags.Int64("antes", 0, "cursor de la página anterior")
	output := flags.String("salida", "", "archivo JSON de salida")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usa pavarotti actividad --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	page, err := store.AuditPage(context.Background(), *before, *limit)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(page)
	})
}
