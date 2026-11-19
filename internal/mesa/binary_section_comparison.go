package mesa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const binarySectionComparisonPattern = "POST /api/secciones-binarias/comparar"

func binarySectionComparisonRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc(binarySectionComparisonPattern, func(w http.ResponseWriter, r *http.Request) {
		const maxBody = 2*triaje.MaxBinaryBytes + (64 << 10)
		if r.ContentLength > maxBody {
			http.Error(w, "La solicitud supera el tamaño permitido", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		form, err := r.MultipartReader()
		if err != nil {
			binarySectionError(w, analisis.ErrBinarySectionRequest)
			return
		}
		comparison, err := loadSectionComparison(r, store, form)
		if err != nil {
			binarySectionError(w, err)
			return
		}
		respond(w, comparison)
	})
}

func loadSectionComparison(r *http.Request, store *caso.Store, form *multipart.Reader) (analisis.BinarySectionComparison, error) {
	part, err := form.NextPart()
	if err != nil || part.FormName() != "seleccion" {
		return analisis.BinarySectionComparison{}, multipartSectionError(err)
	}
	const maxSelection = 4 << 10
	data, err := io.ReadAll(io.LimitReader(part, maxSelection+1))
	if err != nil {
		return analisis.BinarySectionComparison{}, multipartSectionError(err)
	}
	var selection analisis.BinarySectionSelection
	if len(data) > maxSelection || json.Unmarshal(data, &selection) != nil {
		return analisis.BinarySectionComparison{}, analisis.ErrBinarySectionRequest
	}
	read := func(name string, target analisis.BinarySectionTarget) (analisis.BinarySectionInventory, error) {
		file, err := form.NextPart()
		if err != nil || file.FormName() != "archivo_"+name || file.FileName() == "" {
			return analisis.BinarySectionInventory{}, multipartSectionError(err)
		}
		inventory, err := analisis.ReadBinarySections(r.Context(), store, target, file)
		if err != nil {
			return analisis.BinarySectionInventory{}, fmt.Errorf("archivo %s · %w", name, err)
		}
		return inventory, nil
	}
	base, err := read("base", selection.Baseline)
	if err != nil {
		return analisis.BinarySectionComparison{}, err
	}
	current, err := read("actual", selection.Current)
	if err != nil {
		return analisis.BinarySectionComparison{}, err
	}
	if _, err := form.NextPart(); !errors.Is(err, io.EOF) {
		return analisis.BinarySectionComparison{}, multipartSectionError(err)
	}
	return analisis.CompareBinarySections(base, current)
}

func multipartSectionError(err error) error {
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		return err
	}
	return analisis.ErrBinarySectionRequest
}

func binarySectionError(w http.ResponseWriter, err error) {
	var limit *http.MaxBytesError
	switch {
	case errors.As(err, &limit):
		http.Error(w, "La solicitud supera el tamaño permitido", http.StatusRequestEntityTooLarge)
	case errors.Is(err, analisis.ErrBinarySectionRequest):
		http.Error(w, "Adjunta los dos archivos originales y sus revisiones", http.StatusBadRequest)
	case errors.Is(err, analisis.ErrBinarySectionPair), errors.Is(err, analisis.ErrBinarySectionInventory),
		errors.Is(err, analisis.ErrBinarySectionWork), errors.Is(err, analisis.ErrBinaryWindowSample):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "El expediente no contiene una de las revisiones", http.StatusNotFound)
	default:
		http.Error(w, "No se pudieron comparar las secciones de los binarios", http.StatusInternalServerError)
	}
}
