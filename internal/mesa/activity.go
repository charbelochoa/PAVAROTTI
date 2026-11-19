package mesa

import (
	"errors"
	"net/http"
	"strconv"

	"pavarotti/internal/caso"
)

func activityRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/actividad", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		limit := 50
		var before int64
		var err error
		if value := query.Get("limite"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil {
				http.Error(w, caso.ErrAuditPage.Error(), http.StatusBadRequest)
				return
			}
		}
		if value := query.Get("antes"); value != "" {
			before, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				http.Error(w, caso.ErrAuditPage.Error(), http.StatusBadRequest)
				return
			}
		}
		page, err := store.AuditPage(r.Context(), before, limit)
		switch {
		case errors.Is(err, caso.ErrAuditPage):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, caso.ErrAuditUnavailable):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, "No se pudo consultar la actividad del expediente", http.StatusInternalServerError)
		default:
			respond(w, page)
		}
	})
}
