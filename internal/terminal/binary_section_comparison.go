package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pavarotti/internal/analisis"
)

func terminalCompareSections(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("comparar-secciones",
		"comparar-secciones --base-id ID --base archivo --actual-id ID --actual archivo [--base-revision N --actual-revision N] [--salida comparacion.json]", stderr)
	var selection analisis.BinarySectionSelection
	flags.StringVar(&selection.Baseline.RecordID, "base-id", "", "registro del binario base")
	flags.IntVar(&selection.Baseline.Revision, "base-revision", 1, "revisión del binario base")
	flags.StringVar(&selection.Current.RecordID, "actual-id", "", "registro del binario actual")
	flags.IntVar(&selection.Current.Revision, "actual-revision", 1, "revisión del binario actual")
	basePath := flags.String("base", "", "archivo binario base")
	currentPath := flags.String("actual", "", "archivo binario actual")
	output := flags.String("salida", "", "ruta de un archivo de comparación nuevo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *basePath == "" || *currentPath == "" ||
		selection.Baseline.RecordID == "" || selection.Current.RecordID == "" ||
		selection.Baseline.Revision < 1 || selection.Current.Revision < 1 {
		return errors.New("indica los dos archivos y sus revisiones con comparar-secciones --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	read := func(label, path string, target analisis.BinarySectionTarget) (analisis.BinarySectionInventory, error) {
		file, err := openRegularFile(path)
		if err != nil {
			return analisis.BinarySectionInventory{}, err
		}
		defer file.Close()
		inventory, err := analisis.ReadBinarySections(ctx, store, target, file)
		if err != nil {
			return analisis.BinarySectionInventory{}, fmt.Errorf("archivo %s · %w", label, err)
		}
		return inventory, nil
	}
	base, err := read("base", *basePath, selection.Baseline)
	if err != nil {
		return err
	}
	current, err := read("actual", *currentPath, selection.Current)
	if err != nil {
		return err
	}
	comparison, err := analisis.CompareBinarySections(base, current)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(comparison)
	})
}
