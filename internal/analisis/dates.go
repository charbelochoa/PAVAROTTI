package analisis

import (
	"errors"
	"time"

	"pavarotti/internal/caso"
)

func parseUTCPeriod(first, last string) (caso.EvidencePeriod, error) {
	start, startErr := time.Parse(time.DateOnly, first)
	end, endErr := time.Parse(time.DateOnly, last)
	if startErr != nil || endErr != nil || start.Year() < 1 || end.Year() < 1 || end.Before(start) {
		return caso.EvidencePeriod{}, errors.New("indica fechas UTC en orden, con formato AAAA-MM-DD")
	}
	return caso.EvidencePeriod{Start: start, End: end.AddDate(0, 0, 1)}, nil
}
