package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pavarotti/internal/analisis"
)

func terminalQueue(command string, args []string, stdout, stderr io.Writer, open openExpediente) error {
	usage, count := command, 0
	if command == "informe" || command == "cancelar" {
		usage, count = command+" <ID>", 1
	}
	flags := terminalFlags(command, usage, stderr)
	priority, reportJSON := 1, false
	if command == "encolar" {
		flags.IntVar(&priority, "prioridad", 1, "prioridad entre 0 (baja) y 2 (alta)")
	}
	if command == "informe" {
		flags.BoolVar(&reportJSON, "json", false, "emite el informe como JSON")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != count {
		return fmt.Errorf("uso: pavarotti %s", usage)
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	output := json.NewEncoder(stdout)
	output.SetIndent("", "  ")
	switch command {
	case "ejecutor":
		return analisis.RunQueue(ctx, store)
	case "encolar":
		job, err := analisis.Enqueue(ctx, store, priority)
		if err != nil {
			return err
		}
		return output.Encode(job)
	case "tareas":
		jobs, err := store.AnalysisJobs(ctx)
		if err != nil {
			return err
		}
		return output.Encode(jobs)
	case "cancelar":
		job, err := store.CancelAnalysis(ctx, flags.Arg(0))
		if err != nil {
			return err
		}
		return output.Encode(job)
	case "informe":
		job, err := store.AnalysisJob(ctx, flags.Arg(0))
		if err != nil {
			return err
		}
		if job.State != "succeeded" {
			return fmt.Errorf("el informe aún no está disponible (%s)", job.State)
		}
		if reportJSON {
			return output.Encode(job.Result)
		}
		text, err := analisis.JobText(job)
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, terminalMultiline(text))
		return err
	default:
		return fmt.Errorf("comando de análisis desconocido: %q", command)
	}
}
