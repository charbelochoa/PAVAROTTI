package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func terminalWatchlists(args []string, stdout, stderr io.Writer, open openExpediente) error {
	const usage = "seguimiento [listar | crear | agregar | quitar | eliminar] [--lista nombre] [--tipo tipo --valor activo] [--json]"
	action := "listar"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	flags := terminalFlags("seguimiento", usage, stderr)
	name := flags.String("lista", "", "nombre de la lista de seguimiento")
	var asset analisis.AssetKey
	flags.StringVar(&asset.Type, "tipo", "", "dominio, ipv4, ipv6, red, sha256, sha1 o md5")
	flags.StringVar(&asset.Value, "valor", "", "valor exacto del activo")
	asJSON := flags.Bool("json", false, "emite resultados estructurados")
	if err := flags.Parse(args); err != nil {
		return err
	}
	operation := caso.WatchAction(action)
	withAsset := operation == caso.WatchAdd || operation == caso.WatchRemove
	if flags.NArg() != 0 || (action != "listar" && *name == "") ||
		(withAsset && (asset.Type == "" || asset.Value == "")) || (!withAsset && asset != (analisis.AssetKey{})) {
		return errors.New("uso: pavarotti " + usage)
	}
	switch operation {
	case "listar", caso.WatchCreate, caso.WatchDelete, caso.WatchAdd, caso.WatchRemove:
	default:
		return errors.New("uso: pavarotti " + usage)
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if action != "listar" {
		changed, err := analisis.ChangeWatchlist(ctx, store, *name, operation, asset)
		if err != nil {
			return err
		}
		if *asJSON {
			return encoder.Encode(map[string]bool{"changed": changed})
		}
		if changed {
			_, err = fmt.Fprintln(stdout, "Seguimiento actualizado")
		} else {
			_, err = fmt.Fprintln(stdout, "La lista ya está en ese estado")
		}
		return err
	}
	if *name == "" {
		lists, err := store.Watchlists(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return encoder.Encode(lists)
		}
		if len(lists) == 0 {
			_, err := fmt.Fprintln(stdout, "Sin listas de seguimiento")
			return err
		}
		for _, list := range lists {
			if _, err := fmt.Fprintf(stdout, "%s · %d activos\n", list.Name, list.Count); err != nil {
				return err
			}
		}
		return nil
	}
	review, err := analisis.ReviewWatchlist(ctx, store, *name)
	if err != nil {
		return err
	}
	if *asJSON {
		return encoder.Encode(review)
	}
	if _, err := fmt.Fprintf(stdout, "%s · %d activos\n", review.Name, len(review.Rows)); err != nil {
		return err
	}
	for _, row := range review.Rows {
		if _, err := fmt.Fprintf(stdout, "%s · %s · %d registros · %d coberturas\n", row.Type, row.Value, row.Count, row.Coverage); err != nil {
			return err
		}
		if row.Latest != nil {
			if _, err := fmt.Fprintf(stdout, "  %s · %s · rev. %d · %s\n", row.Latest.Time, row.Latest.ID, row.Latest.Revision, terminalText(row.Latest.Title)); err != nil {
				return err
			}
		}
	}
	return nil
}
