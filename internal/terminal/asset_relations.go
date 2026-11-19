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

func terminalAssetRelations(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("relaciones-activo", "relaciones-activo --tipo <tipo> --valor <activo> [--desde AAAA-MM-DD --hasta AAAA-MM-DD] [--salida archivo.json]", stderr)
	var criteria analisis.AssetRelationCriteria
	flags.StringVar(&criteria.Type, "tipo", "", "dominio, ipv4, ipv6, red, sha256, sha1 o md5")
	flags.StringVar(&criteria.Value, "valor", "", "valor exacto del activo")
	flags.StringVar(&criteria.From, "desde", "", "fecha UTC inicial")
	flags.StringVar(&criteria.To, "hasta", "", "fecha UTC final inclusiva")
	output := flags.String("salida", "", "ruta nueva para el informe JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || criteria.Type == "" || criteria.Value == "" {
		return errors.New("usa pavarotti relaciones-activo --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := analisis.RelateAsset(ctx, store, criteria)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	})
}
