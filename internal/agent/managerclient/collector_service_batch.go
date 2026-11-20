package managerclient

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

type LogBatch struct {
	Identity jobcontext.JobIdentity
	// GitHubCheckRunID is sent next to the identity so the manager can bind
	// it to the OIDC claim. It is not part of the job key.
	GitHubCheckRunID string
	Scope            managerv1beta1.Scope
	Type             managerv1beta1.LogType
	Records          [][]byte
	FlushAt          time.Time
}

func BuildCollectorIngestLogBatch(batch LogBatch) (*managerv1beta1.IngestLogBatch, error) {
	if len(batch.Records) == 0 {
		return nil, fmt.Errorf("collector ingest log batch has no records")
	}

	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	wroteRecords := false
	for _, record := range batch.Records {
		if len(record) == 0 {
			continue
		}
		wroteRecords = true
		if _, err := gzipWriter.Write(record); err != nil {
			_ = gzipWriter.Close()
			return nil, fmt.Errorf("gzip collector ingest log batch record: %w", err)
		}
		if _, err := gzipWriter.Write([]byte("\n")); err != nil {
			_ = gzipWriter.Close()
			return nil, fmt.Errorf("gzip collector ingest log batch newline: %w", err)
		}
	}
	if !wroteRecords {
		_ = gzipWriter.Close()
		return nil, fmt.Errorf("collector ingest log batch has no non-empty records")
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close gzip collector ingest log batch: %w", err)
	}

	identity := protoconv.ToProtoJobIdentity(batch.Identity)
	identity.GithubCheckRunId = batch.GitHubCheckRunID
	return &managerv1beta1.IngestLogBatch{
		JobIdentity:     identity,
		Scope:           batch.Scope,
		LogType:         batch.Type,
		CompressedJsonl: compressed.Bytes(),
		FlushAt:         timestamppb.New(batch.FlushAt.UTC()),
	}, nil
}
