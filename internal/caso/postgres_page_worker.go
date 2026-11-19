package caso

import (
	"context"
	"sync"
	"time"
)

const pagePreparationTimeout = 8 * time.Second

type postgresPageWorker struct {
	mu      sync.Mutex
	enabled bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func (s *Store) EnableBackgroundPagePreparation() {
	if s.db == nil {
		return
	}
	s.searchWork.enable()
	s.httpWork.enable()
}

func (work *postgresPageWorker) enable() {
	work.mu.Lock()
	work.enabled = true
	work.mu.Unlock()
}

func (s *Store) pageProjectionForRequest(ctx context.Context, work *postgresPageWorker, pendingQuery string,
	prepare func(context.Context) (bool, error)) (bool, error) {
	work.mu.Lock()
	enabled := work.enabled
	work.mu.Unlock()
	if !enabled {
		return prepare(ctx)
	}
	var pending bool
	if err := s.db.QueryRowContext(ctx, pendingQuery, s.expediente).Scan(&pending); err != nil {
		return false, err
	}
	if pending {
		work.start(prepare)
	}
	return !pending, nil
}

func (work *postgresPageWorker) start(prepare func(context.Context) (bool, error)) {
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
			step, cancelStep := context.WithTimeout(ctx, pagePreparationTimeout)
			ready, err := prepare(step)
			cancelStep()
			if err != nil || ready {
				return
			}
		}
	}()
}

func (work *postgresPageWorker) stop() {
	work.mu.Lock()
	work.closed = true
	done, cancel := work.done, work.cancel
	work.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
