package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const binaryCitationSchema = "pavarotti.binary-citation.v1"

var errBinaryCitation = errors.New("indica una revisión, un tipo de cita y un índice válidos")

type binaryCitation struct {
	Schema           string `json:"schema"`
	RecordID         string `json:"record_id"`
	Revision         int    `json:"revision"`
	SHA256           string `json:"sha256"`
	InspectionSHA256 string `json:"inspection_sha256"`
	Kind             string `json:"kind"`
	Index            int    `json:"index"`
	Offset           string `json:"offset"`
}

func citeBinary(ctx context.Context, store *caso.Store, id string, revision int, kind string, index int) (binaryCitation, error) {
	if id == "" || revision < 1 || index < 0 || (kind != "seccion" && kind != "cadena" && kind != "simbolo") {
		return binaryCitation{}, errBinaryCitation
	}
	record, err := store.RecordRevision(ctx, id, revision)
	if err != nil {
		return binaryCitation{}, err
	}
	var report triaje.Binary
	if record.Kind != "binario" || record.SHA256 == "" || json.Unmarshal([]byte(record.Details), &report) != nil || report.SHA256 != record.SHA256 {
		return binaryCitation{}, caso.ErrNotFound
	}
	offset := binaryCitationOffset(report, kind, index)
	position, err := strconv.ParseUint(strings.TrimPrefix(offset, "0x"), 16, 64)
	if err != nil || !strings.HasPrefix(offset, "0x") || report.Size <= 0 || position >= uint64(report.Size) {
		return binaryCitation{}, caso.ErrNotFound
	}
	return binaryCitation{Schema: binaryCitationSchema, RecordID: record.ID, Revision: record.Revision, SHA256: record.SHA256,
		InspectionSHA256: caso.Hash([]byte(record.Details)), Kind: kind, Index: index, Offset: offset}, nil
}

func binaryCitationOffset(report triaje.Binary, kind string, index int) string {
	switch kind {
	case "seccion":
		if index < len(report.Sections) && report.Sections[index].File != nil {
			return report.Sections[index].File.Offset
		}
	case "cadena":
		if index < len(report.Strings) {
			return report.Strings[index].Offset
		}
	case "simbolo":
		if index < len(report.Symbols) {
			return report.Symbols[index].Offset
		}
	}
	return ""
}

func binaryCitationRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/registro/{id}/cita-binaria", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		revision, revisionErr := strconv.Atoi(query.Get("revision"))
		index, indexErr := strconv.Atoi(query.Get("indice"))
		if revisionErr != nil || indexErr != nil {
			http.Error(w, errBinaryCitation.Error(), http.StatusBadRequest)
			return
		}
		citation, err := citeBinary(r.Context(), store, r.PathValue("id"), revision, query.Get("tipo"), index)
		switch {
		case errors.Is(err, errBinaryCitation):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, caso.ErrNotFound):
			http.Error(w, "La revisión no contiene esa ubicación física", http.StatusNotFound)
		case err != nil:
			http.Error(w, "No se pudo verificar la cita del binario", http.StatusInternalServerError)
		default:
			respond(w, citation)
		}
	})
}

func terminalBinaryCitation(args []string, stdout, stderr io.Writer, open openExpediente) error {
	flags := terminalFlags("citar-binario", "citar-binario --id ID --revision N --tipo seccion|cadena|simbolo --indice N [--salida archivo.json]", stderr)
	id := flags.String("id", "", "identificador del registro")
	revision := flags.Int("revision", 0, "revisión del registro")
	kind := flags.String("tipo", "", "seccion, cadena o simbolo")
	index := flags.Int("indice", -1, "posición en la lista a partir de 0")
	output := flags.String("salida", "", "archivo JSON de salida")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errBinaryCitation
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	citation, err := citeBinary(context.Background(), store, *id, *revision, *kind, *index)
	if err != nil {
		return err
	}
	return writeExport(stdout, *output, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(citation)
	})
}
