package mesa

import (
	"errors"
	"io"
	"net/http"
	"net/url"

	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

func directoryRoutes(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("POST /api/revision/directorio", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, ingesta.MaxDirectoryBytes+(1<<20))
		parts, err := r.MultipartReader()
		if err != nil {
			directoryError(w, err)
			return
		}
		var review ingesta.DirectoryReview
		for {
			file, err := parts.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				directoryError(w, err)
				return
			}
			if file.FileName() == "" {
				directoryError(w, ingesta.ErrDirectoryPath)
				return
			}
			name, err := url.PathUnescape(file.FormName())
			if err != nil {
				directoryError(w, ingesta.ErrDirectoryPath)
				return
			}
			if err := review.Add(name, file); err != nil {
				directoryError(w, err)
				return
			}
			if err := file.Close(); err != nil {
				directoryError(w, err)
				return
			}
		}
		result, err := review.Save(r.Context(), store)
		if errors.Is(err, ingesta.ErrDirectoryEmpty) {
			directoryError(w, err)
			return
		}
		status, message := http.StatusOK, result.Message()
		if err != nil {
			status, message = http.StatusInternalServerError, "Revisión guardada parcialmente · "+message
		}
		replyJSON(w, status, struct {
			ingesta.DirectoryResult
			Message string `json:"message"`
		}{result, message})
	})
}

func directoryError(w http.ResponseWriter, err error) {
	status, message := http.StatusBadRequest, "Selección de directorio inválida"
	var size *http.MaxBytesError
	switch {
	case errors.Is(err, ingesta.ErrDirectoryLimit), errors.As(err, &size):
		status, message = http.StatusRequestEntityTooLarge, ingesta.ErrDirectoryLimit.Error()
	case errors.Is(err, ingesta.ErrDirectoryPath), errors.Is(err, ingesta.ErrDirectoryEmpty):
		message = err.Error()
	}
	replyJSON(w, status, map[string]string{"message": message})
}
