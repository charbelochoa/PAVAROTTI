package analisis

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"pavarotti/internal/caso"
)

func Enqueue(ctx context.Context, store *caso.Store, priority int) (caso.AnalysisJob, error) {
	if !store.HasAnalysisQueue() {
		return caso.AnalysisJob{}, caso.ErrQueueUnavailable
	}
	if priority < 0 || priority > 2 {
		return caso.AnalysisJob{}, caso.ErrInvalidJob
	}
	snapshot, err := Prepare(ctx, store)
	if err != nil {
		return caso.AnalysisJob{}, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return caso.AnalysisJob{}, err
	}
	return store.EnqueueAnalysis(ctx, snapshot.Fingerprint, snapshot.AgentVersion, priority, data)
}

func RunQueue(ctx context.Context, store *caso.Store) error {
	if !store.HasAnalysisQueue() {
		return caso.ErrQueueUnavailable
	}
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for ctx.Err() == nil {
		claim, found, err := store.ClaimAnalysis(ctx, AgentVersion, networkAgent, legacyAgent)
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			log.Printf("Cola de análisis: %v", err)
		case found:
			executeClaim(ctx, store, claim)
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
		}
	}
	return nil
}

func executeClaim(ctx context.Context, store *caso.Store, claim caso.AnalysisClaim) {
	execution, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	renewal, stopRenewal := context.WithCancel(ctx)
	defer stopRenewal()
	lease := make(chan error, 1)
	go func() {
		err := renewClaim(renewal, store, claim)
		if err != nil {
			cancel()
		}
		lease <- err
	}()
	result, failure := claimResult(execution, claim)
	stopRenewal()
	if err := <-lease; err != nil || ctx.Err() != nil {
		return
	}
	if err := store.FinishAnalysis(ctx, claim, result, failure); err != nil &&
		!errors.Is(err, caso.ErrJobState) && ctx.Err() == nil {
		log.Printf("No se pudo guardar el análisis %s: %v", claim.Job.ID, err)
	}
}

func renewClaim(ctx context.Context, store *caso.Store, claim caso.AnalysisClaim) error {
	ticker := time.NewTicker(caso.AnalysisLease / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewal, cancel := context.WithTimeout(ctx, caso.AnalysisLease/4)
			err := store.RenewAnalysis(renewal, claim)
			cancel()
			if err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
}

func claimResult(ctx context.Context, claim caso.AnalysisClaim) (json.RawMessage, string) {
	var snapshot Snapshot
	if err := json.Unmarshal(claim.Snapshot, &snapshot); err != nil || !supportedAgent(snapshot.AgentVersion) ||
		snapshot.AgentVersion != claim.Job.AgentVersion || snapshot.Fingerprint != claim.Job.Fingerprint {
		return nil, "La instantánea no coincide con la tarea"
	}
	checksum, err := snapshot.checksum(ctx)
	if err != nil || checksum != snapshot.Fingerprint {
		return nil, "No se pudo verificar la huella de entrada"
	}
	report, err := snapshot.Analyze(ctx)
	if err != nil {
		return nil, "No se pudo completar el análisis"
	}
	result, err := json.Marshal(report)
	if err != nil {
		return nil, "No se pudo serializar el informe"
	}
	return result, ""
}
