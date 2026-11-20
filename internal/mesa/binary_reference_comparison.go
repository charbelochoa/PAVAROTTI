package mesa

import (
	"errors"
	"net/http"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const binaryReferenceComparisonPattern = "POST /api/referencias-binarias/comparar"

func binaryReferenceComparisonRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc(binaryReferenceComparisonPattern, func(w http.ResponseWriter, r *http.Request) {
		const maxBody = triaje.MaxBinaryBytes + 2*analisis.MaxBinaryReferenceReportBytes + (64 << 10)
		tooLarge := func() {
			http.Error(w, "La solicitud supera el tamaño permitido", http.StatusRequestEntityTooLarge)
		}
		if r.ContentLength > maxBody {
			tooLarge()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		form, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "Adjunta los dos informes y el archivo original", http.StatusBadRequest)
			return
		}
		readReport := func(name string) (analisis.BinaryReferenceReport, bool) {
			part, err := form.NextPart()
			if err == nil && part.FormName() == name {
				var report analisis.BinaryReferenceReport
				report, err = analisis.ReadBinaryReferenceReport(part)
				if err == nil {
					return report, true
				}
			}
			var limit *http.MaxBytesError
			if errors.As(err, &limit) {
				tooLarge()
			} else {
				http.Error(w, "Adjunta un informe "+name+" en formato JSON", http.StatusBadRequest)
			}
			return analisis.BinaryReferenceReport{}, false
		}
		baseline, valid := readReport("base")
		if !valid {
			return
		}
		current, valid := readReport("actual")
		if !valid {
			return
		}
		original, err := form.NextPart()
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			tooLarge()
			return
		}
		if err != nil || original.FormName() != "archivo" {
			http.Error(w, "Adjunta el archivo binario original", http.StatusBadRequest)
			return
		}
		comparison, err := analisis.CompareBinaryReferences(r.Context(), store, baseline, current, original)
		if r.Context().Err() != nil {
			return
		}
		switch {
		case errors.As(err, &limit):
			tooLarge()
		case errors.Is(err, analisis.ErrBinaryReferenceComparison), errors.Is(err, analisis.ErrBinaryReferenceReport),
			errors.Is(err, analisis.ErrBinaryWindowSample):
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		case errors.Is(err, caso.ErrNotFound):
			http.Error(w, "El expediente no contiene una de las ubicaciones citadas", http.StatusNotFound)
		case err != nil:
			http.Error(w, "No se pudieron comparar los informes de referencias", http.StatusInternalServerError)
		default:
			respond(w, comparison)
		}
	})
}
