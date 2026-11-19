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

func terminalBinaryWindow(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("ventana-binaria", "ventana-binaria --archivo muestra (--id ID --revision N --tipo entrada|simbolo --indice N | --cita cita.json) [--solo-cita] [--salida ventana.json]", stderr)
	var request analisis.BinaryWindowRequest
	flags.StringVar(&request.RecordID, "id", "", "identificador del binario")
	flags.IntVar(&request.Revision, "revision", 0, "revisión del registro")
	flags.StringVar(&request.Kind, "tipo", "", "entrada o simbolo")
	flags.IntVar(&request.Index, "indice", 0, "posición del símbolo desde 0 o número de la imagen Mach-O desde 1")
	path := flags.String("archivo", "", "archivo binario original")
	citationPath := flags.String("cita", "", "archivo JSON de cita de ventana")
	citationOnly := flags.Bool("solo-cita", false, "exporta solo la cita portátil")
	output := flags.String("salida", "", "ruta de un archivo JSON nuevo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || (*citationPath != "" && request != (analisis.BinaryWindowRequest{})) {
		return errors.New("indica el archivo original y una ubicación o cita de ventana")
	}
	file, err := openRegularFile(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var result analisis.BinaryWindowReport
	if *citationPath == "" {
		result, err = analisis.OpenBinaryWindow(ctx, store, request, file)
	} else {
		citation, readErr := readBinaryWindowCitation(*citationPath)
		if readErr != nil {
			return readErr
		}
		result, err = analisis.VerifyBinaryWindow(ctx, store, citation, file)
	}
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if *citationOnly {
			return encoder.Encode(result.Citation)
		}
		return encoder.Encode(result)
	})
}

func readBinaryWindowCitation(path string) (analisis.BinaryWindowCitation, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return analisis.BinaryWindowCitation{}, err
	}
	defer file.Close()
	const limit = 4 << 10
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return analisis.BinaryWindowCitation{}, err
	}
	var citation analisis.BinaryWindowCitation
	if len(data) > limit || json.Unmarshal(data, &citation) != nil || citation.Schema != analisis.BinaryWindowSchema {
		return analisis.BinaryWindowCitation{}, analisis.ErrBinaryWindowCitation
	}
	return citation, nil
}
