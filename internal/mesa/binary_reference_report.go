package mesa

import (
	"errors"
	"net/http"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const binaryReferencePattern = "POST /api/registro/{id}/referencias-binarias"

func binaryReferenceRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc(binaryReferencePattern, func(w http.ResponseWriter, r *http.Request) {
		const maxBody = triaje.MaxBinaryBytes + analisis.MaxBinaryReferenceReportBytes + (64 << 10)
		if r.ContentLength > maxBody {
			http.Error(w, "La solicitud supera el tamaño permitido", http.StatusRequestEntityTooLarge)
			return
		}
		mode := r.URL.Query().Get("modo")
		if mode != "exportar" && mode != "verificar" {
			http.Error(w, "Indica si deseas exportar o verificar el informe", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		form, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "Adjunta el informe y el archivo original", http.StatusBadRequest)
			return
		}
		manifest, err := form.NextPart()
		if err != nil || manifest.FormName() != "informe" {
			http.Error(w, "Adjunta el informe de referencias", http.StatusBadRequest)
			return
		}
		report, err := analisis.ReadBinaryReferenceReport(manifest)
		if err != nil || report.RecordID != r.PathValue("id") {
			http.Error(w, analisis.ErrBinaryReferenceReport.Error(), http.StatusBadRequest)
			return
		}
		sample, err := form.NextPart()
		if err != nil || sample.FormName() != "archivo" {
			http.Error(w, "Adjunta el archivo binario original", http.StatusBadRequest)
			return
		}
		review, err := analisis.ReviewBinaryReferences(r.Context(), store, report, sample, mode == "verificar")
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			http.Error(w, "La solicitud supera el tamaño permitido", http.StatusRequestEntityTooLarge)
		case errors.Is(err, analisis.ErrBinaryReferenceReport), errors.Is(err, analisis.ErrBinaryWindowSample):
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		case errors.Is(err, caso.ErrNotFound):
			http.Error(w, "La revisión no contiene esa ubicación", http.StatusNotFound)
		case err != nil:
			http.Error(w, "No se pudo verificar el informe de referencias", http.StatusInternalServerError)
		default:
			respond(w, review)
		}
	})
}
