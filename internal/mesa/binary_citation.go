package mesa

import (
	"errors"
	"net/http"
	"strconv"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func binaryCitationRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/registro/{id}/cita-binaria", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		revision, revisionErr := strconv.Atoi(query.Get("revision"))
		index, indexErr := strconv.Atoi(query.Get("indice"))
		if revisionErr != nil || indexErr != nil {
			http.Error(w, analisis.ErrBinaryCitation.Error(), http.StatusBadRequest)
			return
		}
		citation, err := analisis.CiteBinary(r.Context(), store, r.PathValue("id"), revision, query.Get("tipo"), index)
		switch {
		case errors.Is(err, analisis.ErrBinaryCitation):
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
