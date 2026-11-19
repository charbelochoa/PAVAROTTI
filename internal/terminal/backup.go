package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pavarotti/internal/caso"
)

func terminalBackup(command string, args []string, stdout, stderr io.Writer, open openExpediente) error {
	if command == "respaldar" {
		return terminalWriteBackup(args, stdout, stderr, open)
	}
	flags := terminalFlags(command, command+" --archivo copia.jsonl", stderr)
	path := flags.String("archivo", "", "archivo de respaldo del expediente")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("indica el archivo mediante --archivo")
	}
	file, err := openBackupFile(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var summary caso.BackupSummary
	if command == "verificar-respaldo" {
		summary, err = caso.InspectCaseBackup(ctx, file)
	} else {
		store, openErr := open()
		if openErr != nil {
			return openErr
		}
		defer store.Close()
		summary, err = store.RestoreCase(ctx, file)
	}
	if err != nil {
		return err
	}
	return printBackupSummary(stdout, summary)
}

func openBackupFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("elige un archivo local regular")
	}
	return os.Open(path)
}

func terminalWriteBackup(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("respaldar", "respaldar --salida copia.jsonl", stderr)
	output := flags.String("salida", "", "ruta de un archivo nuevo de respaldo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" {
		return errors.New("indica un archivo nuevo mediante --salida")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var summary caso.BackupSummary
	if err := writeExport(stdout, *output, func(writer io.Writer) error {
		summary, err = store.BackupCase(ctx, writer)
		if err != nil {
			return err
		}
		if file, ok := writer.(*os.File); ok {
			return file.Sync()
		}
		return nil
	}); err != nil {
		return err
	}
	return printBackupSummary(stdout, summary)
}

func printBackupSummary(stdout io.Writer, summary caso.BackupSummary) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}
