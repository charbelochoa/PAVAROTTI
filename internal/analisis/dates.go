package analisis

import (
	"errors"
	"time"
)

type utcPeriod struct {
	start, end time.Time
}

func parseUTCPeriod(first, last string) (utcPeriod, error) {
	start, startErr := time.Parse(time.DateOnly, first)
	end, endErr := time.Parse(time.DateOnly, last)
	if startErr != nil || endErr != nil || start.Year() < 1 || end.Year() < 1 || end.Before(start) {
		return utcPeriod{}, errors.New("indica fechas UTC en orden, con formato AAAA-MM-DD")
	}
	return utcPeriod{start: start, end: end.AddDate(0, 0, 1)}, nil
}

func (period utcPeriod) includes(stamp time.Time) bool {
	return !stamp.Before(period.start) && stamp.Before(period.end)
}
