package joblogs

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

// JobStartLogInput carries the context for one scope's job start record.
type JobStartLogInput struct {
	ScopeLogContext
	// StartedAt is the record timestamp. Zero means now.
	StartedAt time.Time
}

// MarshalJobStartLogEntry builds the JSON job_start record for one scope.
func MarshalJobStartLogEntry(in JobStartLogInput) ([]byte, error) {
	startedAt := in.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	message := &logv1beta1.JobStartLogEntry{
		Timestamp:      timestamppb.New(startedAt.UTC()),
		LogType:        proto.String(logtype.JobStart.Wire()),
		ServiceName:    proto.String(logtype.ServiceName),
		ServiceVersion: proto.String(version.Current),
		SchemaVersion:  proto.String(logtype.JobStartSchemaVersion),
		LogId:          proto.String(newLogID()),
		Job:            protoconv.ToLogContext(in.Identity, in.Metadata),
		Scope:          proto.String(string(in.Scope)),
		RunnerType:     proto.String(in.RunnerType),
		ConfigRevision: proto.String(configRevisionOrAbsent(in.ConfigRevision)),
	}
	return logJSONMarshal.Marshal(message)
}
