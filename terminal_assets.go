package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"pavarotti/internal/analisis"
)

func terminalAssets(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("activos", "activos [--tipo <tipo>] [--valor <activo> | --buscar <texto>] [--json]", stderr)
	var query analisis.AssetQuery
	flags.StringVar(&query.Type, "tipo", "", "dominio, ipv4, ipv6, red, sha256, sha1 o md5")
	flags.StringVar(&query.Value, "valor", "", "valor exacto del activo para abrir su ficha")
	flags.StringVar(&query.Search, "buscar", "", "texto que debe contener el valor")
	flags.StringVar(&query.After, "despues", "", "cursor devuelto por la página anterior")
	flags.IntVar(&query.Limit, "limite", 50, "resultados por página, de 1 a 100")
	asJSON := flags.Bool("json", false, "emite resultados estructurados")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || query.Limit < 1 || query.Limit > 100 {
		return errors.New("usa pavarotti activos --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if query.Value != "" {
		detail, err := analisis.DescribeAsset(ctx, store, query)
		if err != nil {
			return err
		}
		if *asJSON {
			return encoder.Encode(detail)
		}
		if _, err := fmt.Fprintf(stdout, "%s · %s\nRegistros directos %d · indicadores %d · cobertura %d\n",
			detail.Type, detail.Value, detail.Count, detail.Indicators, detail.Coverage); err != nil {
			return err
		}
		for _, row := range detail.Rows {
			if _, err := fmt.Fprintf(stdout, "%s · %s · %s · %s · rev. %d · %s\n",
				row.Time, row.Kind, row.Role, row.ID, row.Revision, terminalText(row.Title)); err != nil {
				return err
			}
		}
		return nextAssetPage(stdout, detail.Next)
	}
	page, err := analisis.ListAssets(ctx, store, query)
	if err != nil {
		return err
	}
	if *asJSON {
		return encoder.Encode(page)
	}
	if len(page.Rows) == 0 {
		_, err := fmt.Fprintln(stdout, "Sin activos para mostrar.")
		return err
	}
	for _, row := range page.Rows {
		if _, err := fmt.Fprintf(stdout, "%s · %s · %d registro(s) · %d indicador(es)\n",
			row.Type, row.Value, row.Count, row.Indicators); err != nil {
			return err
		}
	}
	return nextAssetPage(stdout, page.Next)
}

func nextAssetPage(output io.Writer, cursor string) error {
	if cursor == "" {
		return nil
	}
	_, err := fmt.Fprintf(output, "Página siguiente · --despues %q\n", cursor)
	return err
}
