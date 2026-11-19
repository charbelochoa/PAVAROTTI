package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

const terminalUsage = `PAVAROTTI · expediente Blue Team

Uso: pavarotti [opciones globales] <comando> [argumentos]

  listar    Consulta el expediente con filtros por tipo y texto.
  importar  Incorpora capturas HAR, hallazgos, binarios, código Go o listas de indicadores.
  nota      Registra una nota del analista.
  editar    Actualiza una nota con su revisión actual.
  historial Consulta las versiones previas de una nota.
  analizar  Correlaciona la evidencia del expediente.
  exportar  Exporta el expediente como JSON o CSV.
  ayuda     Muestra esta ayuda.

Sin comando se abre la interfaz web. Usa <comando> --help para ver sus opciones.
`

type openExpediente func() (*caso.Store, error)

func terminal(args []string, stdout, stderr io.Writer, open func() (*caso.Store, error)) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	var err error
	switch args[0] {
	case "ayuda", "help":
		if len(args) != 1 {
			err = errors.New("uso: pavarotti ayuda")
			break
		}
		_, err = io.WriteString(stdout, terminalUsage)
	case "listar":
		err = terminalRecords("listar", args[1:], stdout, stderr, open)
	case "importar":
		err = terminalImport(args[1:], stdout, stderr, open)
	case "nota":
		err = terminalNote(args[1:], stdout, stderr, open)
	case "editar":
		err = terminalEdit(args[1:], stdout, stderr, open)
	case "historial":
		err = terminalHistory(args[1:], stdout, stderr, open)
	case "analizar":
		err = terminalAnalyze(args[1:], stdout, stderr, open)
	case "exportar":
		err = terminalRecords("exportar", args[1:], stdout, stderr, open)
	default:
		err = fmt.Errorf("comando desconocido %q; usa pavarotti ayuda", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	return true, err
}

func terminalFlags(name, usage string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Uso: pavarotti %s\n", usage)
		flags.PrintDefaults()
	}
	return flags
}

func terminalImport(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("importar", "importar <har|hallazgos|binario|codigo|indicadores> <archivo>", stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("uso: pavarotti importar <har|hallazgos|binario|codigo|indicadores> <archivo>")
	}
	path := flags.Arg(1)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("elige un archivo local regular")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	records, err := ingesta.Parse(flags.Arg(0), file)
	if err != nil {
		return err
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Save(records); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Importación registrada · %d registro(s)\n", len(records))
	return err
}

func terminalNote(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("nota", "nota --titulo <título> --texto <nota> [--origen <referencia>]", stderr)
	title := flags.String("titulo", "", "título de la nota")
	details := flags.String("texto", "", "texto de la nota")
	source := flags.String("origen", "", "referencia local o URL informativa")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usa pavarotti nota --help")
	}
	record, err := ingesta.Nota(*title, *source, *details)
	if err != nil {
		return err
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Save([]caso.Record{record}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Nota guardada")
	return err
}

func terminalRecords(command string, args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags(command, command+" [opciones]", stderr)
	kind := flags.String("tipo", "", "filtra por tipo: har, hallazgo, tráfico, binario, código, indicador, nota")
	query := flags.String("buscar", "", "busca texto en el título, origen, ID, huella y detalle")
	format := "tabla"
	var output string
	var limit int
	var asJSON bool
	if command == "exportar" {
		flags.StringVar(&format, "formato", "json", "formato de exportación: json o csv")
		flags.StringVar(&output, "salida", "", "archivo nuevo para la exportación")
	}
	if command == "listar" {
		flags.BoolVar(&asJSON, "json", false, "muestra el resultado como JSON")
		flags.IntVar(&limit, "limite", 50, "número de registros, 0 para todos")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || limit < 0 {
		return fmt.Errorf("usa pavarotti %s --help", command)
	}
	if command == "exportar" && format != "json" && format != "csv" {
		return errors.New("elige un formato de exportación json o csv")
	}
	if asJSON {
		format = "json"
	}
	normalizedKind, err := recordKind(*kind)
	if err != nil {
		return err
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	records, err := store.Records()
	if err != nil {
		return err
	}
	records = filterRecords(records, normalizedKind, *query)
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return writeRecords(stdout, output, format, records)
}

func recordKind(kind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "har", "archivo har":
		return "archivo HAR", nil
	case "trafico", "tráfico":
		return "tráfico", nil
	case "hallazgo", "hallazgos":
		return "hallazgo", nil
	case "codigo", "código":
		return "código", nil
	case "", "binario", "nota", "indicador":
		return strings.ToLower(strings.TrimSpace(kind)), nil
	default:
		return "", fmt.Errorf("tipo desconocido %q", kind)
	}
}

func filterRecords(records []caso.Record, kind string, query string) []caso.Record {
	results := make([]caso.Record, 0, len(records))
	query = strings.ToLower(strings.TrimSpace(query))
	for _, record := range records {
		if kind != "" && record.Kind != kind {
			continue
		}
		text := strings.Join([]string{record.ID, record.Title, record.Source, record.SourceID, record.SHA256,
			record.Details, strings.Join(record.Signals, "\n")}, "\n")
		if query == "" || strings.Contains(strings.ToLower(text), query) {
			results = append(results, record)
		}
	}
	slices.SortStableFunc(results, func(a, b caso.Record) int {
		left, _ := time.Parse(time.RFC3339Nano, a.Time)
		right, _ := time.Parse(time.RFC3339Nano, b.Time)
		return right.Compare(left)
	})
	return results
}

func writeRecords(stdout io.Writer, output, format string, records []caso.Record) error {
	if output == "" {
		return encodeRecords(stdout, format, records)
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = errors.Join(encodeRecords(file, format, records), file.Close())
	if err != nil {
		return errors.Join(err, os.Remove(output))
	}
	return nil
}

func encodeRecords(output io.Writer, format string, records []caso.Record) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(records)
	case "csv":
		return encodeCSV(output, records)
	}
	if len(records) == 0 {
		_, err := fmt.Fprintln(output, "Sin registros para los filtros indicados.")
		return err
	}
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tREV\tFECHA\tTIPO\tTÍTULO\tORIGEN")
	for _, record := range records {
		fmt.Fprintf(table, "%s\t%d\t%s\t%s\t%s\t%s\n", terminalText(record.ID), record.Revision,
			terminalText(record.Time), terminalText(record.Kind), terminalText(record.Title), terminalText(record.Source))
	}
	return table.Flush()
}

func encodeCSV(output io.Writer, records []caso.Record) error {
	writer := csv.NewWriter(output)
	if err := writer.Write([]string{"id", "revision", "fecha", "tipo", "id_origen", "titulo", "origen", "sha256", "detalle",
		"senales", "metodo", "estado_http", "tipo_contenido", "duracion_ms"}); err != nil {
		return err
	}
	for _, record := range records {
		row := []string{record.ID, strconv.Itoa(record.Revision), record.Time, record.Kind, record.SourceID, record.Title, record.Source,
			record.SHA256, record.Details, strings.Join(record.Signals, "\n"), "", "", "", ""}
		if traffic := record.Traffic; traffic != nil {
			row[10], row[11], row[12], row[13] = traffic.Method, strconv.Itoa(traffic.Status), traffic.Type,
				strconv.FormatInt(traffic.Millis, 10)
		}
		for i, cell := range row {
			row[i] = csvLiteral(cell)
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func csvLiteral(text string) string {
	trimmed := strings.TrimLeftFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
	if strings.HasPrefix(text, "\t") || strings.HasPrefix(text, "\r") || strings.HasPrefix(text, "\n") ||
		(trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + text
	}
	return text
}

func terminalText(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, text)
}
