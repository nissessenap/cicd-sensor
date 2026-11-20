package kernelio

import (
	"context"
	"errors"

	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

var ErrNotSupported = errors.New("not supported")

// Config contains the cgroup v2 root detected by KernelTracker.
type Config struct {
	CgroupV2RootPath string
	// EnableHTTPRequest enables cleartext capture and the HTTP uprobe runtime.
	// It does not gate BPF load: LoadAndAssign verifies all programs at startup.
	EnableHTTPRequest bool
}

// KernelIO is the BPF program/map/ringbuf I/O boundary. It stays as an
// interface so engine loop tests can run without loading kernel programs.
type KernelIO interface {
	// netBlockToken is stored with the tracking entry and inherited in-kernel
	// by child and staged cgroups; 0 means blocking is disabled.
	PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64, netBlockToken uint32) error
	DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error
	PutCgroupBasenameInStagingMap(ctx context.Context, basename string, netBlockToken uint32) error
	DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error
	// InstallNetBlockProgram makes program the one the connect hooks
	// evaluate for cgroups carrying token, replacing any earlier one.
	InstallNetBlockProgram(ctx context.Context, token uint32, program netblock.Program) error
	// DeleteNetBlockProgram stops enforcement for token. A token without a
	// program is not an error.
	DeleteNetBlockProgram(ctx context.Context, token uint32) error
	// QueueHTTPUprobeReconciliation takes ownership of an active userspace
	// cgroup-ID snapshot and schedules a non-blocking maps-liveness sweep.
	// It is a no-op when HTTP uprobe capture is disabled.
	QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64)
	StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error
	Close() error
}

// KernelSample is one raw ringbuf sample payload from the BPF program.
// The bytes are valid only during the handler call; retainers must copy them.
type KernelSample []byte

// KernelSampleHandler receives raw samples from the BPF ring buffer.
type KernelSampleHandler func(context.Context, KernelSample) error

const (
	TrackedCgroupsMapName = "tracked_cgroups"
	StagingMapName        = "staging_map"
	StagingKeyLen         = 256
	StagingMaxEntries     = 1024
)
