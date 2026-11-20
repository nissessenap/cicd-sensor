//go:build !linux

package kernelio

import (
	"context"
	"log/slog"

	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

var _ = configureBPFProgramSpec

func New(logger *slog.Logger, config Config) (KernelIO, error) {
	_ = logger
	_ = config
	return &StubKernelIO{}, nil
}

type StubKernelIO struct{}

func (kernelIO *StubKernelIO) PutCgroupIDInTrackedCgroupsMap(context.Context, uint64, uint32) error {
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) InstallNetBlockProgram(context.Context, uint32, netblock.Program) error {
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) DeleteNetBlockProgram(context.Context, uint32) error {
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error {
	_ = ctx
	_ = cgroupIDs
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) PutCgroupBasenameInStagingMap(context.Context, string, uint32) error {
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error {
	_ = ctx
	_ = basenames
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64) {
	_ = activeCgroupIDs
}

func (kernelIO *StubKernelIO) StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error {
	_ = ctx
	_ = handle
	return ErrNotSupported
}

func (kernelIO *StubKernelIO) Close() error {
	return nil
}
