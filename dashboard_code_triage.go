package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"pavarotti/internal/caso"
)

func codeTriageRoutes(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/registro/{id}/triaje", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		id := r.PathValue("id")
		var items []caso.CodeDisposition
		var err error
		if query.Has("regla") || query.Has("linea") || query.Has("columna") {
			line, lineErr := strconv.Atoi(query.Get("linea"))
			column, columnErr := strconv.Atoi(query.Get("columna"))
			if lineErr != nil || columnErr != nil || line < 1 || column < 1 || query.Get("regla") == "" {
				http.Error(w, "Identifica la señal por regla, línea y columna", http.StatusBadRequest)
				return
			}
			items, err = store.CodeHistory(r.Context(), id, caso.FindingKey{Rule: query.Get("regla"), Line: line, Column: column})
		} else {
			items, err = store.CodeClassifications(r.Context(), id)
		}
		if err != nil {
			codeTriageError(w, err)
			return
		}
		respond(w, items)
	})
	mux.HandleFunc("PATCH /api/registro/{id}/triaje", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			caso.FindingKey
			Revision *int   `json:"revision"`
			Status   string `json:"status"`
			Reason   string `json:"reason"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || input.Revision == nil || decoder.Decode(new(any)) != io.EOF {
			codeTriageError(w, caso.ErrInvalidTriage)
			return
		}
		saved, err := store.ClassifyCode(r.Context(), r.PathValue("id"), input.FindingKey, *input.Revision, input.Status, input.Reason)
		if err != nil {
			codeTriageError(w, err)
			return
		}
		respond(w, saved)
	})
}

func codeTriageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "Señal de código inexistente", http.StatusNotFound)
	case errors.Is(err, caso.ErrRevisionConflict):
		http.Error(w, "La clasificación cambió. Vuelve a abrir la señal para ver la revisión actual.", http.StatusConflict)
	case errors.Is(err, caso.ErrInvalidTriage):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "No se pudo leer o guardar la clasificación", http.StatusInternalServerError)
	}
}
