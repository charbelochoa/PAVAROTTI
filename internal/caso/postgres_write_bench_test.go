package caso

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

func BenchmarkPostgresSustainedWrites(b *testing.B) {
	for _, scenario := range []struct {
		name   string
		actors int
		cases  int
	}{
		{"uno", 1, 1},
		{"cuatro-compartido", 4, 1},
		{"cuatro-expedientes", 4, 4},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
			stores := make([]*Store, scenario.cases)
			for index := range stores {
				stores[index] = openAuditTestAt(b, dsn)
			}
			ctx := b.Context()
			writers := make([]sustainedWriter, scenario.actors)
			expected := make([]int, len(stores))
			for index := range writers {
				caseIndex := index % len(stores)
				writers[index] = prepareSustainedWriter(b, stores[caseIndex], index)
				expected[caseIndex]++
			}
			for index := range b.N {
				expected[index%len(writers)%len(stores)]++
			}
			times := make([]time.Duration, b.N)
			var startLSN string
			if err := stores[0].db.QueryRowContext(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&startLSN); err != nil {
				b.Fatal(err)
			}
			errs := make(chan error, len(writers))
			var group sync.WaitGroup
			b.ResetTimer()
			for worker, writer := range writers {
				group.Go(func() {
					for job := worker; job < b.N; job += len(writers) {
						started := time.Now()
						if err := writer.write(job); err != nil {
							errs <- err
							return
						}
						times[job] = time.Since(started)
					}
				})
			}
			group.Wait()
			b.StopTimer()
			close(errs)
			for err := range errs {
				b.Fatal(err)
			}
			var walBytes float64
			if err := stores[0].db.QueryRowContext(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), $1::pg_lsn)::float8`, startLSN).Scan(&walBytes); err != nil {
				b.Fatal(err)
			}
			for index, store := range stores {
				var count, first, last int
				err := store.db.QueryRowContext(ctx, `SELECT count(*), min(position), max(position)
					FROM pavarotti_audit_events WHERE expediente = $1`, store.expediente).Scan(&count, &first, &last)
				if err != nil || count != expected[index] || first != 1 || last != count {
					b.Fatalf("auditoría del expediente %d: %d eventos, posiciones %d–%d, esperados %d, error %v",
						index, count, first, last, expected[index], err)
				}
			}
			edits := make([]time.Duration, 0, b.N-b.N/5)
			imports := make([]time.Duration, 0, b.N/5)
			for index, elapsed := range times {
				if sustainedImport(index) {
					imports = append(imports, elapsed)
				} else {
					edits = append(edits, elapsed)
				}
			}
			reportWriteLatencies(b, "edición", edits)
			reportWriteLatencies(b, "ingesta", imports)
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "tx/s")
			b.ReportMetric(walBytes/float64(b.N), "wal-B/op")
		})
	}
}

type sustainedWriter struct {
	store *Store
	ctx   context.Context
	note  Record
}

func prepareSustainedWriter(b *testing.B, store *Store, index int) sustainedWriter {
	b.Helper()
	ctx := store.AuditContext(b.Context(), SharedAccount{Name: fmt.Sprintf("analista-%d", index+1), Role: SharedAnalyst})
	note := Record{Kind: "nota", Title: fmt.Sprintf("Nota de medición %d", index+1), Time: Now(), Details: "Versión inicial"}
	if result, err := store.SaveEvidence(ctx, []Record{note}); err != nil || result.Imported != 1 {
		b.Fatalf("preparar nota: %+v, %v", result, err)
	}
	data, err := json.Marshal([]Record{note})
	if err != nil {
		b.Fatal(err)
	}
	key := Hash(data)
	note.ID, note.Revision, note.UpdatedAt = key+"-1", 1001, note.Time
	data, err = json.Marshal(note)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO pavarotti_note_revisions (expediente, batch_key, ordinal, revision, snapshot)
		SELECT $1, $2, 1, r, jsonb_set($3::jsonb, '{revision}', to_jsonb(r)) FROM generate_series(2, $4::int) r`,
		store.expediente, key, data, note.Revision); err != nil {
		b.Fatal(err)
	}
	return sustainedWriter{store: store, ctx: ctx, note: note}
}

func sustainedImport(index int) bool {
	return index%5 == 4
}

func (writer *sustainedWriter) write(index int) error {
	if sustainedImport(index) {
		stamp := Now()
		records := make([]Record, 16)
		for offset := range records {
			value := fmt.Sprintf("host-%d-%d.example.invalid", index, offset)
			records[offset] = Record{Kind: "indicador", Time: stamp, Title: value, Source: value}
		}
		result, err := writer.store.SaveEvidence(writer.ctx, records)
		if err != nil || result.Imported != len(records) {
			return fmt.Errorf("guardar lote %d: %+v, %v", index, result, err)
		}
		return nil
	}
	note := writer.note
	edited, err := writer.store.EditContext(writer.ctx, note.ID, note.Revision, note.Title, "", fmt.Sprintf("Revisión sintética %d", index))
	if err != nil || edited.Revision != note.Revision+1 {
		return fmt.Errorf("guardar revisión %d: %d, %v", note.Revision+1, edited.Revision, err)
	}
	writer.note = edited
	return nil
}

func reportWriteLatencies(b *testing.B, operation string, times []time.Duration) {
	if len(times) == 0 {
		return
	}
	slices.Sort(times)
	for _, percentile := range []int{50, 95, 99} {
		index := int(math.Ceil(float64(len(times))*float64(percentile)/100)) - 1
		b.ReportMetric(float64(times[index])/float64(time.Millisecond), fmt.Sprintf("%s-p%d-ms", operation, percentile))
	}
}
