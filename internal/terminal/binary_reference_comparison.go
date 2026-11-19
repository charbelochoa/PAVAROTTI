package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pavarotti/internal/analisis"
)

func terminalCompareReferences(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("comparar-referencias", "comparar-referencias --base antes.json --actual despues.json --archivo muestra [--salida comparacion.json]", stderr)
	basePath := flags.String("base", "", "informe JSON de referencia base")
	currentPath := flags.String("actual", "", "informe JSON de referencia actual")
	path := flags.String("archivo", "", "archivo binario original")
	output := flags.String("salida", "", "ruta de un archivo de comparación nuevo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *basePath == "" || *currentPath == "" || *path == "" {
		return errors.New("indica los dos informes y el archivo original")
	}
	baseline, err := readBinaryReferenceFile(*basePath)
	if err != nil {
		return err
	}
	current, err := readBinaryReferenceFile(*currentPath)
	if err != nil {
		return err
	}
	sample, err := openRegularFile(*path)
	if err != nil {
		return err
	}
	defer sample.Close()
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	comparison, err := analisis.CompareBinaryReferences(ctx, store, baseline, current, sample)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(comparison)
	})
}
