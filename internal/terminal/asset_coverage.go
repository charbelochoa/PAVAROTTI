package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"pavarotti/internal/analisis"
)

func terminalAssetCoverage(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("cobertura-activo", "cobertura-activo --tipo <tipo> --valor <activo> --desde AAAA-MM-DD --hasta AAAA-MM-DD [--salida archivo.json]", stderr)
	var criteria analisis.AssetCoverageCriteria
	flags.StringVar(&criteria.Type, "tipo", "", "dominio, ipv4, ipv6, red, sha256, sha1 o md5")
	flags.StringVar(&criteria.Value, "valor", "", "valor exacto del activo")
	flags.StringVar(&criteria.From, "desde", "", "fecha UTC inicial")
	flags.StringVar(&criteria.To, "hasta", "", "fecha UTC final inclusiva")
	output := flags.String("salida", "", "ruta nueva para el informe JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usa pavarotti cobertura-activo --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	report, err := analisis.CoverAsset(context.Background(), store, criteria)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	})
}
