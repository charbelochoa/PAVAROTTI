package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/trafico"
	"pavarotti/internal/triaje"
)

//go:embed ui/* licenses/*
var resources embed.FS

const uploadLimit = 32 << 20

type settings struct {
	Version string `json:"version"`
	Proxy   string `json:"proxy,omitempty"`
	Target  string `json:"target,omitempty"`
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
	for _, name := range []string{"Apache-2.0.txt", "NOTICE"} {
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
		r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "No se pudo leer el archivo. Límite: 32 MiB.", http.StatusBadRequest)
			return
		}
		var records []caso.Record
		switch r.PathValue("tipo") {
		case "har":
			records, err = trafico.ImportHAR(data)
		case "hallazgos":
			records, err = caso.Findings(data)
		case "binario":
			if len(data) == 0 {
				http.Error(w, "El archivo está vacío", http.StatusBadRequest)
				return
			}
			result := triaje.Inspect(data)
			details, _ := json.MarshalIndent(result, "", "  ")
			records = []caso.Record{{Kind: "binario", Time: caso.Now(), Title: result.Format,
				SHA256: result.SHA256, Details: string(details)}}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		save(w, store, records)
	})
	mux.HandleFunc("POST /api/nota", func(w http.ResponseWriter, r *http.Request) {
		var note struct {
			Title   string `json:"title"`
			Source  string `json:"source"`
			Details string `json:"details"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&note); err != nil || strings.TrimSpace(note.Title) == "" ||
			len(note.Title) > 160 || strings.TrimSpace(note.Details) == "" {
			http.Error(w, "Introduce un título y una nota", http.StatusBadRequest)
			return
		}
		save(w, store, []caso.Record{{Kind: "nota", Time: caso.Now(), Title: strings.TrimSpace(note.Title),
			Source: strings.TrimSpace(note.Source), Details: strings.TrimSpace(note.Details)}})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != host || (r.Method == http.MethodPost && r.Header.Get("Origin") != "http://"+host) {
			http.Error(w, "Origen incorrecto", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
