package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pavarotti/internal/caso"
)

func terminalAuditRetention(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("retener-actividad", "retener-actividad --antes AAAA-MM-DD [--aplicar --respaldo copia.jsonl]", stderr)
	date := flags.String("antes", "", "fecha de corte, a las 00:00 UTC")
	apply := flags.Bool("aplicar", false, "retira del expediente los eventos anteriores a la fecha")
	archive := flags.String("respaldo", "", "copia del mismo expediente requerida al aplicar")
	if err := flags.Parse(args); err != nil {
		return err
	}
	before, err := time.Parse(time.DateOnly, *date)
	if err != nil || flags.NArg() != 0 {
		return errors.New("indica --antes con una fecha AAAA-MM-DD")
	}
	if *apply && *archive == "" {
		return errors.New("indica el archivo de respaldo mediante --respaldo para aplicar la retención")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var result caso.AuditRetentionResult
	if *apply {
		file, err := openBackupFile(*archive)
		if err != nil {
			return err
		}
		defer file.Close()
		applied, err := store.ApplyAuditRetention(ctx, before, file)
		if err != nil {
			return err
		}
		result = applied
	} else {
		result, err = store.PreviewAuditRetention(ctx, before)
		if err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
