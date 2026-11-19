package terminal

import (
	"context"
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

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

const terminalUsage = `PAVAROTTI · expediente Blue Team

Uso: pavarotti [opciones globales] <comando> [argumentos]

  listar    Consulta el expediente con filtros por tipo y texto.
  activos   Busca dominios, direcciones, redes y huellas y abre sus fichas.
  importar  Incorpora evidencia, código Go o manifiestos de dependencias.
  revisar   Revisa código Go y manifiestos de un directorio local.
  triaje    Consulta o clasifica señales de código con su justificación.
  citar-binario Exporta la ubicación verificada de un binario como JSON.
  usuarios  Administra cuentas de acceso para el expediente PostgreSQL.
  actividad Consulta y exporta la actividad del expediente PostgreSQL.
  nota      Registra una nota del analista.
  editar    Actualiza una nota con su revisión actual.
  historial Consulta las versiones previas de una nota.
  analizar  Correlaciona la evidencia del expediente.
  encolar   Programa un análisis persistente en PostgreSQL.
  tareas    Lista las tareas de análisis en JSON.
  informe   Abre el informe de una tarea terminada.
  cancelar  Cancela una tarea de análisis pendiente o activa.
  ejecutor  Ejecuta la cola de análisis para este expediente.
  exportar  Exporta el expediente como STIX 2.1, JSON o CSV.
  migrar-local Copia un expediente local y su historial a PostgreSQL.
  ayuda     Muestra esta ayuda.

Sin comando se abre la interfaz web. Usa <comando> --help para ver sus opciones.
`

type openExpediente func() (*caso.Store, error)

func Run(args []string, stdout, stderr io.Writer, open func() (*caso.Store, error)) (bool, error) {
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
	case "activos":
		err = terminalAssets(args[1:], stdout, stderr, open)
	case "importar":
		err = terminalImport(args[1:], stdout, stderr, open)
	case "revisar":
		err = terminalDirectory(args[1:], stdout, stderr, open)
	case "triaje":
		err = terminalCodeTriage(args[1:], stdout, stderr, open)
	case "citar-binario":
		err = terminalBinaryCitation(args[1:], stdout, stderr, open)
	case "usuarios":
		err = terminalSharedAccounts(args[1:], stdout, stderr, open)
	case "actividad":
		err = terminalActivity(args[1:], stdout, stderr, open)
	case "nota":
		err = terminalNote(args[1:], stdout, stderr, open)
	case "editar":
		err = terminalEdit(args[1:], stdout, stderr, open)
	case "historial":
		err = terminalHistory(args[1:], stdout, stderr, open)
	case "analizar":
		err = terminalAnalyze(args[1:], stdout, stderr, open)
	case "encolar", "tareas", "informe", "cancelar", "ejecutor":
		err = terminalQueue(args[0], args[1:], stdout, stderr, open)
	case "exportar":
		err = terminalRecords("exportar", args[1:], stdout, stderr, open)
	case "migrar-local":
		err = terminalMigrate(args[1:], stdout, stderr, open)
	default:
		err = fmt.Errorf("comando desconocido %q; usa pavarotti ayuda", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	return true, err
}

func terminalMigrate(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("migrar-local", "migrar-local <carpeta>", stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("uso: pavarotti -postgres <URL> migrar-local <carpeta>")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	count, err := store.ImportLocal(flags.Arg(0))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Migración completada · %d registro(s) nuevos\n", count)
	return err
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
	flags := terminalFlags("importar", "importar <har|hallazgos|binario|codigo|gomod|npmlock|indicadores|dns|rdap|stix> <archivo>", stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("usa pavarotti importar --help")
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

	records, err := ingesta.ParseNamed(flags.Arg(0), file, path)
	if err != nil {
		return err
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	result, err := store.SaveEvidence(context.Background(), records)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, result.Message())
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
	kind := flags.String("tipo", "", "filtra por tipo: har, hallazgo, tráfico, binario, código, dependencias, indicador, dns, rdap, stix, nota")
	query := flags.String("buscar", "", "busca texto en el título, origen, ID, huella y detalle")
	format := "tabla"
	var output string
	var limit int
	var asJSON bool
	if command == "exportar" {
		flags.StringVar(&format, "formato", "json", "formato de exportación: json, csv o stix")
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
	if command == "exportar" && format != "json" && format != "csv" && format != "stix" {
		return errors.New("elige un formato de exportación json, csv o stix")
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
	if format == "stix" {
		search := strings.ToLower(strings.TrimSpace(*query))
		data, stats, err := analisis.ExportSTIX(context.Background(), store, func(record caso.Record) bool {
			return matchesExportFilter(record, normalizedKind, search)
		})
		if err != nil {
			return err
		}
		if err := writeExport(stdout, output, func(writer io.Writer) error {
			_, err := writer.Write(data)
			return err
		}); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stderr, stats.Message())
		return err
	}
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
	case "", "binario", "nota", "dependencias", "indicador", "dns", "rdap", "stix":
		return strings.ToLower(strings.TrimSpace(kind)), nil
	default:
		return "", fmt.Errorf("tipo desconocido %q", kind)
	}
}

func filterRecords(records []caso.Record, kind string, query string) []caso.Record {
	results := make([]caso.Record, 0, len(records))
	query = strings.ToLower(strings.TrimSpace(query))
	for _, record := range records {
		if matchesExportFilter(record, kind, query) {
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

func matchesExportFilter(record caso.Record, kind, query string) bool {
	if kind != "" && record.Kind != kind {
		return false
	}
	if query == "" {
		return true
	}
	if record.MatchesDependency(query) {
		return true
	}
	text := strings.Join([]string{record.ID, record.Title, record.Source, record.SourceID, record.SHA256,
		record.Details, strings.Join(record.Signals, "\n")}, "\n")
	return strings.Contains(strings.ToLower(text), query)
}

func writeRecords(stdout io.Writer, output, format string, records []caso.Record) error {
	return writeExport(stdout, output, func(writer io.Writer) error { return encodeRecords(writer, format, records) })
}

func writeExport(stdout io.Writer, output string, encode func(io.Writer) error) error {
	if output == "" {
		return encode(stdout)
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = errors.Join(encode(file), file.Close())
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
