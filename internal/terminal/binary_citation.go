package terminal

import (
	"context"
	"encoding/json"
	"io"

	"pavarotti/internal/analisis"
)

func terminalBinaryCitation(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("citar-binario", "citar-binario --id ID --revision N --tipo seccion|cadena|simbolo|instruccion --indice N [--salida archivo.json]", stderr)
	id := flags.String("id", "", "identificador del registro")
	revision := flags.Int("revision", 0, "revisión del registro")
	kind := flags.String("tipo", "", "seccion, cadena, simbolo o instruccion")
	index := flags.Int("indice", -1, "posición en la lista a partir de 0")
	output := flags.String("salida", "", "archivo JSON de salida")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return analisis.ErrBinaryCitation
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	citation, err := analisis.CiteBinary(context.Background(), store, *id, *revision, *kind, *index)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(citation)
	})
}
