package caso

import (
	"os"
	"sync"
	"time"
)

const maxLocalBatchDates = 8192

type localBatchDates struct {
	mu      sync.Mutex
	entries map[string]batchDates
}

type batchDates struct {
	modified time.Time
	size     int64
	all      timeBounds
	http     timeBounds
}

type timeBounds struct {
	earliest, latest time.Time
	valid            bool
}

func (index *localBatchDates) lookup(key string, info os.FileInfo) (batchDates, bool) {
	index.mu.Lock()
	defer index.mu.Unlock()
	dates, found := index.entries[key]
	return dates, found && dates.size == info.Size() && dates.modified.Equal(info.ModTime())
}

func (index *localBatchDates) remember(key string, info os.FileInfo, records []Record) {
	dates := batchDates{size: info.Size(), modified: info.ModTime()}
	for _, record := range records {
		stamp, err := time.Parse(time.RFC3339Nano, record.Time)
		if err != nil {
			continue
		}
		dates.all.add(stamp)
		if record.Traffic != nil {
			dates.http.add(stamp)
		}
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	if index.entries == nil {
		index.entries = make(map[string]batchDates)
	}
	if _, had := index.entries[key]; had || len(index.entries) < maxLocalBatchDates {
		index.entries[key] = dates
	}
}

func (rangeOfTimes *timeBounds) add(stamp time.Time) {
	if !rangeOfTimes.valid || stamp.Before(rangeOfTimes.earliest) {
		rangeOfTimes.earliest = stamp
	}
	if !rangeOfTimes.valid || stamp.After(rangeOfTimes.latest) {
		rangeOfTimes.latest = stamp
	}
	rangeOfTimes.valid = true
}

func (dates batchDates) matches(filter EvidenceFilter) bool {
	bounds := dates.all
	if filter.HTTP {
		bounds = dates.http
	}
	if !bounds.valid {
		return false
	}
	for _, period := range filter.Periods {
		if !bounds.latest.Before(period.Start) && bounds.earliest.Before(period.End) {
			return true
		}
	}
	return false
}
