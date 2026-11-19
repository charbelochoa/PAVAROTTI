package caso

import (
	"context"
	"sync"
	"time"
)

type postgresSearchWorker struct {
	mu      sync.Mutex
	enabled bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func (s *Store) EnableBackgroundSearchPreparation() {
	if s.db == nil {
		return
	}
	s.searchWork.mu.Lock()
	s.searchWork.enabled = true
	s.searchWork.mu.Unlock()
}

func (s *Store) searchPageForRequest(ctx context.Context) (bool, error) {
	s.searchWork.mu.Lock()
	enabled := s.searchWork.enabled
	s.searchWork.mu.Unlock()
	if !enabled {
		return s.prepareSearchPage(ctx)
	}
	var pending bool
	if err := s.db.QueryRowContext(ctx, searchPagePending, s.expediente).Scan(&pending); err != nil {
		return false, err
	}
	if pending {
		s.startSearchWorker()
	}
	return !pending, nil
}

func (s *Store) startSearchWorker() {
	work := &s.searchWork
	work.mu.Lock()
	defer work.mu.Unlock()
	if work.closed || work.done != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	work.cancel, work.done = cancel, make(chan struct{})
	go func() {
		defer func() {
			cancel()
			work.mu.Lock()
			close(work.done)
			work.done, work.cancel = nil, nil
			work.mu.Unlock()
		}()
		for ctx.Err() == nil {
			step, cancelStep := context.WithTimeout(ctx, 8*time.Second)
			ready, err := s.prepareSearchPage(step)
			cancelStep()
			if err != nil || ready {
				return
			}
		}
	}()
}

func (work *postgresSearchWorker) stop() {
	work.mu.Lock()
	work.closed = true
	done, cancel := work.done, work.cancel
	work.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
