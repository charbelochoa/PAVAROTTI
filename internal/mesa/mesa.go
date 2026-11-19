package mesa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/trafico"
)

type Settings struct {
	Version       string              `json:"version"`
	Proxy         string              `json:"proxy,omitempty"`
	Target        string              `json:"target,omitempty"`
	AnalysisQueue bool                `json:"analysis_queue"`
	Activity      bool                `json:"activity,omitempty"`
	Shared        bool                `json:"shared,omitempty"`
	Case          string              `json:"case,omitempty"`
	Account       *caso.SharedAccount `json:"account,omitempty"`
}

type noteInput struct {
	Title    string `json:"title"`
	Source   string `json:"source"`
	Details  string `json:"details"`
	Revision int    `json:"revision"`
}

func Handler(host string, config Settings, store *caso.Store, resources fs.FS) http.Handler {
	store.EnableBackgroundPagePreparation()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, resources, "ui/index.html")
	})
	for _, name := range []string{"app.css", "app.js", "http-comparison.js", "asset-coverage.js", "asset-relations.js", "watchlists.js", "binary-references.js", "binary-reference-comparison.js", "binary-section-comparison.js", "binary-instructions.js", "binary-window.js", "mascara.svg", "icono.png", "credits.json"} {
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
	mux.HandleFunc("GET /api/app", func(w http.ResponseWriter, r *http.Request) {
		state := config
		state.Activity = store.HasAuditLog()
		state.Case = store.SharedCase()
		if account, ok := r.Context().Value(sharedAccountKey{}).(caso.SharedAccount); ok {
			state.Account = &account
		}
		respond(w, state)
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
	mux.HandleFunc("GET /api/registro/pagina", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		request := caso.PageRequest{
			Kind: query.Get("tipo"), Search: query.Get("buscar"), After: query.Get("despues"),
			HTTPSource: query.Get("captura"), HTTPMethod: query.Get("metodo"), HTTPRule: query.Get("regla_http"),
			HTTPFrom: query.Get("desde"), HTTPTo: query.Get("hasta"),
		}
		if size := query.Get("limite"); size != "" {
			limit, err := strconv.Atoi(size)
			if err != nil || limit < 1 || limit > 100 {
				http.Error(w, "El límite debe estar entre 1 y 100", http.StatusBadRequest)
				return
			}
			request.Limit = limit
		}
		if raw := query.Get("clase_http"); raw != "" {
			class, err := strconv.Atoi(raw)
			if err != nil || class < 1 || class > 5 {
				http.Error(w, "La clase HTTP debe estar entre 1 y 5", http.StatusBadRequest)
				return
			}
			request.HTTPClass = class
		}
		page, err := store.Page(r.Context(), request)
		if errors.Is(err, caso.ErrInvalidPage) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "No se pudo consultar la página del expediente", http.StatusInternalServerError)
			return
		}
		respond(w, page)
	})
	mux.HandleFunc("GET /api/http/reglas", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, trafico.PassiveRules())
	})
	mux.HandleFunc("GET /api/registro/resumen", func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.Summary(r.Context())
		if err != nil {
			http.Error(w, "No se pudo consultar el resumen del expediente", http.StatusInternalServerError)
			return
		}
		respond(w, stats)
	})
	mux.HandleFunc("GET /api/registro/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var record caso.Record
		var err error
		if raw := r.URL.Query().Get("revision"); raw != "" {
			revision, parseErr := strconv.Atoi(raw)
			if parseErr != nil || revision < 1 || strconv.Itoa(revision) != raw {
				http.Error(w, "La revisión debe ser un entero positivo", http.StatusBadRequest)
				return
			}
			record, err = store.RecordRevision(r.Context(), id, revision)
		} else {
			record, err = store.Record(r.Context(), id)
		}
		if errors.Is(err, caso.ErrNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "No se pudo consultar el registro", http.StatusInternalServerError)
			return
		}
		record.Review = record.StaticReview()
		respond(w, record)
	})
	mux.HandleFunc("POST /api/archivo/{tipo}", func(w http.ResponseWriter, r *http.Request) {
		name, _ := url.PathUnescape(r.Header.Get("X-Pavarotti-Filename"))
		records, err := ingesta.ParseNamed(r.PathValue("tipo"), r.Body, name)
		if err != nil {
			if errors.Is(err, ingesta.ErrSize) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := store.SaveEvidence(r.Context(), records)
		if err != nil {
			http.Error(w, "No se pudo guardar el expediente", http.StatusInternalServerError)
			return
		}
		respond(w, struct {
			caso.SaveResult
			Message string `json:"message"`
		}{result, result.Message()})
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
		save(w, r, store, []caso.Record{record})
	})
	mux.HandleFunc("PATCH /api/nota/{id}", func(w http.ResponseWriter, r *http.Request) {
		var note noteInput
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
			http.Error(w, "Nota inválida", http.StatusBadRequest)
			return
		}
		record, err := store.EditContext(r.Context(), r.PathValue("id"), note.Revision, note.Title, note.Source, note.Details)
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
		snapshot, err := analisis.Prepare(r.Context(), store)
		if errors.Is(err, analisis.ErrLimit) || errors.Is(err, analisis.ErrSnapshotBytes) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if err != nil {
			http.Error(w, "No se pudo preparar el expediente", http.StatusInternalServerError)
			return
		}
		report, err := snapshot.Analyze(r.Context())
		if err != nil {
			http.Error(w, "No se pudo analizar el expediente", http.StatusInternalServerError)
			return
		}
		respond(w, map[string]any{"report": report, "text": report.Text()})
	})
	analysisQueueRoutes(mux, store)
	assetRoutes(mux, store)
	watchlistRoutes(mux, store)
	stixRoutes(mux, store)
	directoryRoutes(mux, store)
	codeTriageRoutes(mux, store)
	binaryCitationRoute(mux, store)
	binaryWindowRoute(mux, store)
	binaryReferenceRoute(mux, store)
	binaryReferenceComparisonRoute(mux, store)
	binarySectionComparisonRoute(mux, store)
	activityRoute(mux, store)
	httpComparisonRoute(mux, store)
	var handler http.Handler = mux
	origin := "http://" + host
	if config.Shared {
		origin = "https://" + host
		handler = sharedDashboard(mux, store, origin, resources)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if !strings.EqualFold(r.Host, host) || (config.Shared && r.TLS == nil) ||
			(dashboardMutation(r.Method) && r.Header.Get("Origin") != origin) {
			http.Error(w, "Origen incorrecto", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func dashboardMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
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
	replyJSON(w, http.StatusOK, data)
}

func save(w http.ResponseWriter, r *http.Request, store *caso.Store, records []caso.Record) {
	if _, err := store.SaveEvidence(r.Context(), records); err != nil {
		http.Error(w, "No se pudo guardar el expediente", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"message": fmt.Sprintf("Guardado · %d registro(s)", len(records))})
}
