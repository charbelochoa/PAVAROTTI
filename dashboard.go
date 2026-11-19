package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

//go:embed ui/* licenses/*
var resources embed.FS

type settings struct {
	Version string `json:"version"`
	Proxy   string `json:"proxy,omitempty"`
	Target  string `json:"target,omitempty"`
}

type noteInput struct {
	Title    string `json:"title"`
	Source   string `json:"source"`
	Details  string `json:"details"`
	Revision int    `json:"revision"`
}

func dashboard(host string, config settings, store *caso.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, resources, "ui/index.html")
	})
	for _, name := range []string{"app.css", "app.js", "mascara.svg", "icono.png", "credits.json"} {
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, resources, "ui/"+name)
		})
	}
	for _, name := range []string{"Apache-2.0.txt", "NOTICE", "DEPENDENCIAS.txt"} {
		mux.HandleFunc("GET /licencias/"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.ServeFileFS(w, r, resources, "licenses/"+name)
		})
	}
	mux.HandleFunc("GET /api/app", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, config)
	})
	mux.HandleFunc("GET /api/registro", func(w http.ResponseWriter, _ *http.Request) {
		records, err := store.Records()
		if err != nil {
			http.Error(w, "No se pudo leer el expediente", http.StatusInternalServerError)
			return
		}
		slices.SortStableFunc(records, func(a, b caso.Record) int { return strings.Compare(b.Time, a.Time) })
		respond(w, records)
	})
	mux.HandleFunc("POST /api/archivo/{tipo}", func(w http.ResponseWriter, r *http.Request) {
		records, err := ingesta.Parse(r.PathValue("tipo"), r.Body)
		if err != nil {
			if errors.Is(err, ingesta.ErrSize) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		save(w, store, records)
	})
	mux.HandleFunc("POST /api/nota", func(w http.ResponseWriter, r *http.Request) {
		var note noteInput
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
			http.Error(w, "Introduce un título y una nota", http.StatusBadRequest)
			return
		}
		record, err := ingesta.Nota(note.Title, note.Source, note.Details)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		save(w, store, []caso.Record{record})
	})
	mux.HandleFunc("PATCH /api/nota/{id}", func(w http.ResponseWriter, r *http.Request) {
		var note noteInput
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
			http.Error(w, "Nota inválida", http.StatusBadRequest)
			return
		}
		record, err := store.Edit(r.PathValue("id"), note.Revision, note.Title, note.Source, note.Details)
		if err != nil {
			editError(w, err)
			return
		}
		respond(w, record)
	})
	mux.HandleFunc("GET /api/nota/{id}/historial", func(w http.ResponseWriter, r *http.Request) {
		records, err := store.History(r.PathValue("id"))
		if err != nil {
			editError(w, err)
			return
		}
		respond(w, records)
	})
	mux.HandleFunc("POST /api/analisis", func(w http.ResponseWriter, r *http.Request) {
		records, err := store.Records()
		if err == nil {
			var report analisis.Report
			report, err = analisis.Analyze(r.Context(), records)
			if err == nil {
				respond(w, map[string]any{"report": report, "text": report.Text()})
				return
			}
			if errors.Is(err, analisis.ErrLimit) {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
		}
		http.Error(w, "No se pudo analizar el expediente", http.StatusInternalServerError)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		if r.Host != host || (mutating && r.Header.Get("Origin") != "http://"+host) {
			http.Error(w, "Origen incorrecto", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func editError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "Registro inexistente", http.StatusNotFound)
	case errors.Is(err, caso.ErrRevisionConflict):
		http.Error(w, "La nota cambió. Actualiza el expediente antes de editar de nuevo.", http.StatusConflict)
	case errors.Is(err, caso.ErrReadOnly):
		http.Error(w, "La evidencia importada está protegida", http.StatusForbidden)
	case errors.Is(err, caso.ErrInvalidEdit):
		http.Error(w, "Introduce una nota válida y su número de revisión", http.StatusBadRequest)
	default:
		http.Error(w, "No se pudo guardar o leer la nota", http.StatusInternalServerError)
	}
}

func respond(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}

func save(w http.ResponseWriter, store *caso.Store, records []caso.Record) {
	if err := store.Save(records); err != nil {
		http.Error(w, "No se pudo guardar el expediente", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"message": fmt.Sprintf("Guardado · %d registro(s)", len(records))})
}
