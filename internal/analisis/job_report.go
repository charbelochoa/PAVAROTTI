package analisis

import (
	"encoding/json"

	"pavarotti/internal/caso"
)

func JobText(job caso.AnalysisJob) (string, error) {
	if job.State != "succeeded" {
		return "", nil
	}
	var report Report
	if err := json.Unmarshal(job.Result, &report); err != nil {
		return "", err
	}
	return report.Text(), nil
}
