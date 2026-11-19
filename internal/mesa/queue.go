package mesa

import (
	"encoding/json"
	"errors"
	"net/http"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func analysisQueueRoutes(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("POST /api/analisis/tareas", func(w http.ResponseWriter, r *http.Request) {
		payload := struct {
			Priority int `json:"priority"`
		}{Priority: 1}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			queueError(w, caso.ErrInvalidJob)
			return
		}
		job, err := analisis.Enqueue(r.Context(), store, payload.Priority)
		if err != nil {
			queueError(w, err)
			return
		}
		w.Header().Set("Location", "/api/analisis/tareas/"+job.ID)
		replyJSON(w, http.StatusAccepted, job)
	})
	mux.HandleFunc("GET /api/analisis/tareas", func(w http.ResponseWriter, r *http.Request) {
		jobs, err := store.AnalysisJobs(r.Context())
		if err != nil {
			queueError(w, err)
			return
		}
		respond(w, jobs)
	})
	mux.HandleFunc("GET /api/analisis/tareas/{id}", func(w http.ResponseWriter, r *http.Request) {
		job, err := store.AnalysisJob(r.Context(), r.PathValue("id"))
		if err != nil {
			queueError(w, err)
			return
		}
		text, err := analisis.JobText(job)
		if err != nil {
			queueError(w, err)
			return
		}
		respond(w, map[string]any{"job": job, "text": text})
	})
	mux.HandleFunc("POST /api/analisis/tareas/{id}/cancelar", func(w http.ResponseWriter, r *http.Request) {
		job, err := store.CancelAnalysis(r.Context(), r.PathValue("id"))
		if err != nil {
			queueError(w, err)
			return
		}
		respond(w, job)
	})
}

func replyJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func queueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "Tarea inexistente", http.StatusNotFound)
	case errors.Is(err, caso.ErrQueueUnavailable), errors.Is(err, caso.ErrJobState):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, caso.ErrInvalidJob):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, analisis.ErrLimit), errors.Is(err, analisis.ErrSnapshotBytes):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		http.Error(w, "No se pudo consultar o actualizar la cola de análisis", http.StatusInternalServerError)
	}
}
