package reconciler

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Metrics holds the reconciler's counters and serves them in the Prometheus
// text exposition format. The zero value is ready to use.
type Metrics struct {
	findingsNoStart           atomic.Uint64
	findingsNoSummary         atomic.Uint64
	unjoinableRecords         atomic.Uint64
	invalidRecords            atomic.Uint64
	lateRecords               atomic.Uint64
	webhookSignatureFailures  atomic.Uint64
	reconcileErrors           atomic.Uint64
	recordsWithoutProviderJob atomic.Int64
}

func (m *Metrics) countFinding(verdict Verdict) {
	switch verdict {
	case VerdictNoStart:
		m.findingsNoStart.Add(1)
	case VerdictNoSummary:
		m.findingsNoSummary.Add(1)
	}
}

// ServeHTTP writes every metric in the Prometheus text format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	const prefix = "cicd_sensor_reconciler_"
	fmt.Fprintf(w, "# HELP %sfindings_total Completed jobs reported with missing sensor telemetry.\n", prefix)
	fmt.Fprintf(w, "# TYPE %sfindings_total counter\n", prefix)
	fmt.Fprintf(w, "%sfindings_total{verdict=%q} %d\n", prefix, VerdictNoStart, m.findingsNoStart.Load())
	fmt.Fprintf(w, "%sfindings_total{verdict=%q} %d\n", prefix, VerdictNoSummary, m.findingsNoSummary.Load())
	counter := func(name, help string, value uint64) {
		fmt.Fprintf(w, "# HELP %s%s %s\n# TYPE %s%s counter\n%s%s %d\n", prefix, name, help, prefix, name, prefix, name, value)
	}
	counter("unjoinable_records_total", "Sensor records dropped because they carry no GitHub check run ID.", m.unjoinableRecords.Load())
	counter("invalid_records_total", "Sensor records dropped because their identity attributes are missing or malformed.", m.invalidRecords.Load())
	counter("late_records_total", "Sensor records that arrived after their job already had a verdict.", m.lateRecords.Load())
	counter("webhook_signature_failures_total", "Webhook requests rejected for a missing or invalid signature.", m.webhookSignatureFailures.Load())
	counter("reconcile_errors_total", "Reconcile passes that ended in an error.", m.reconcileErrors.Load())
	fmt.Fprintf(w, "# HELP %srecords_without_provider_job Jobs with sensor records older than the grace period and no workflow_job event.\n", prefix)
	fmt.Fprintf(w, "# TYPE %srecords_without_provider_job gauge\n", prefix)
	fmt.Fprintf(w, "%srecords_without_provider_job %d\n", prefix, m.recordsWithoutProviderJob.Load())
}
