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

func terminalBinaryReferences(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("referencias-binario", "referencias-binario --informe referencias.json --archivo muestra [--generar] [--salida verificado.json]", stderr)
	manifest := flags.String("informe", "", "informe JSON de referencias entrantes")
	path := flags.String("archivo", "", "archivo binario original")
	generate := flags.Bool("generar", false, "sella un borrador de informe tras verificar sus referencias")
	output := flags.String("salida", "", "ruta de un archivo de informe nuevo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifest == "" || *path == "" {
		return errors.New("indica el informe y el archivo original")
	}
	report, err := readBinaryReferenceFile(*manifest)
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
	review, err := analisis.ReviewBinaryReferences(ctx, store, report, sample, !*generate)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(review.Report)
	})
}

func readBinaryReferenceFile(path string) (analisis.BinaryReferenceReport, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return analisis.BinaryReferenceReport{}, err
	}
	defer file.Close()
	return analisis.ReadBinaryReferenceReport(file)
}
