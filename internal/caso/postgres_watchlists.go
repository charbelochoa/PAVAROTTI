package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func migrateWatchlists(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS pavarotti_watchlists (
		expediente TEXT PRIMARY KEY,
		state JSONB NOT NULL CHECK (jsonb_typeof(state) = 'object')
	)`)
	return err
}

func (s *Store) postgresWatchState(ctx context.Context) (watchState, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT state FROM pavarotti_watchlists WHERE expediente = $1", s.expediente).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return make(watchState), nil
	}
	if err != nil {
		return nil, err
	}
	return decodeWatchState(data)
}

func lockWatchState(ctx context.Context, tx *sql.Tx, expediente string) (watchState, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO pavarotti_watchlists (expediente, state)
		VALUES ($1, '{}'::jsonb) ON CONFLICT (expediente) DO NOTHING`, expediente)
	if err != nil {
		return nil, err
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, `SELECT state FROM pavarotti_watchlists
		WHERE expediente = $1 FOR UPDATE`, expediente).Scan(&data); err != nil {
		return nil, err
	}
	return decodeWatchState(data)
}

func writeWatchState(ctx context.Context, tx *sql.Tx, expediente string, state watchState) error {
	if len(state) == 0 {
		_, err := tx.ExecContext(ctx, "DELETE FROM pavarotti_watchlists WHERE expediente = $1", expediente)
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE pavarotti_watchlists SET state = $2 WHERE expediente = $1", expediente, data)
	return err
}

func (s *Store) changePostgresWatchlist(ctx context.Context, name string, action WatchAction, asset Indicator) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.beginCaseWrite(ctx, true)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	state, err := lockWatchState(ctx, tx, s.expediente)
	if err != nil {
		return false, err
	}
	changed, err := state.change(name, action, asset)
	if !changed || err != nil {
		return changed, err
	}
	if err := writeWatchState(ctx, tx, s.expediente, state); err != nil {
		return false, err
	}
	target := Hash([]byte(name + "\x00" + asset.Type + "\x00" + asset.Value))
	if err := s.appendAudit(ctx, tx, AuditWatchlist, target, AuditDetails{Status: string(action)}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
