package mesa

import (
	"errors"
	"net/http"
	"strconv"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const binaryWindowPattern = "POST /api/registro/{id}/ventana-binaria"

func binaryWindowRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc(binaryWindowPattern, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		revision, revisionErr := strconv.Atoi(query.Get("revision"))
		index, indexErr := strconv.Atoi(query.Get("indice"))
		if revisionErr != nil || indexErr != nil {
			http.Error(w, analisis.ErrBinaryWindowRequest.Error(), http.StatusBadRequest)
			return
		}
		if r.ContentLength > triaje.MaxBinaryBytes {
			http.Error(w, "El archivo supera los 32 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, triaje.MaxBinaryBytes)
		request := analisis.BinaryWindowRequest{RecordID: r.PathValue("id"), Revision: revision, Kind: query.Get("tipo"), Index: index}
		report, err := analisis.OpenBinaryWindow(r.Context(), store, request, r.Body)
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			http.Error(w, "El archivo supera los 32 MiB", http.StatusRequestEntityTooLarge)
		case errors.Is(err, analisis.ErrBinaryWindowRequest):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, analisis.ErrBinaryWindowSample), errors.Is(err, triaje.ErrInstructionLocation):
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		case errors.Is(err, caso.ErrNotFound):
			http.Error(w, "La revisión no contiene esa ubicación física", http.StatusNotFound)
		case err != nil:
			http.Error(w, "No se pudo abrir la ventana de instrucciones", http.StatusInternalServerError)
		default:
			respond(w, report)
		}
	})
}
