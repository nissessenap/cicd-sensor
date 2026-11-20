package kerneltracker

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

// noopKernelIO and recordingKernelIO are KernelTracker test doubles for the
// KernelIO boundary; they are not KernelIO implementation tests.
type noopKernelIO struct{}

func (noopKernelIO) PutCgroupIDInTrackedCgroupsMap(context.Context, uint64, uint32) error {
	return nil
}

func (noopKernelIO) InstallNetBlockProgram(context.Context, uint32, uint32, netblock.Program) error {
	return nil
}

func (noopKernelIO) ClearNetBlockSlot(context.Context, uint32) error {
	return nil
}

func (noopKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(context.Context, []uint64) error {
	return nil
}

func (noopKernelIO) PutCgroupBasenameInStagingMap(context.Context, string, uint32) error {
	return nil
}

func (noopKernelIO) DeleteCgroupBasenamesFromStagingMap(context.Context, []string) error {
	return nil
}

func (noopKernelIO) QueueHTTPUprobeReconciliation([]uint64) {}

func (noopKernelIO) StartKernelSampleLoop(context.Context, kernelio.KernelSampleHandler) error {
	return kernelio.ErrNotSupported
}

func (noopKernelIO) Close() error {
	return nil
}

type recordingKernelIO struct {
	startErr         error
	putTrackedErr    error
	deleteTrackedErr error
	putStagingErr    error
	deleteStagingErr error
	closeErr         error
	installErr       error
	clearErr         error

	startCalls    int
	putTracked    []uint64
	deleteTracked []uint64
	putStaging    []string
	deleteStaging []string
	// putTrackedSlots and putStagingSlots are parallel to putTracked / putStaging.
	putTrackedSlots []uint32
	putStagingSlots []uint32
	installs        []netBlockInstall
	clearedSlots    []uint32
}

type netBlockInstall struct {
	slot    uint32
	buffer  uint32
	program netblock.Program
}

func (kernelIO *recordingKernelIO) InstallNetBlockProgram(_ context.Context, slot uint32, buffer uint32, program netblock.Program) error {
	if kernelIO.installErr != nil {
		return kernelIO.installErr
	}
	kernelIO.installs = append(kernelIO.installs, netBlockInstall{slot: slot, buffer: buffer, program: program})
	return nil
}

func (kernelIO *recordingKernelIO) ClearNetBlockSlot(_ context.Context, slot uint32) error {
	if kernelIO.clearErr != nil {
		return kernelIO.clearErr
	}
	kernelIO.clearedSlots = append(kernelIO.clearedSlots, slot)
	return nil
}

func (kernelIO *recordingKernelIO) StartKernelSampleLoop(context.Context, kernelio.KernelSampleHandler) error {
	kernelIO.startCalls++
	if kernelIO.startErr != nil {
		return kernelIO.startErr
	}
	return kernelio.ErrNotSupported
}

func (kernelIO *recordingKernelIO) PutCgroupIDInTrackedCgroupsMap(_ context.Context, cgroupID uint64, netBlockSlot uint32) error {
	if kernelIO.putTrackedErr != nil {
		return kernelIO.putTrackedErr
	}
	kernelIO.putTracked = append(kernelIO.putTracked, cgroupID)
	kernelIO.putTrackedSlots = append(kernelIO.putTrackedSlots, netBlockSlot)
	return nil
}

func (kernelIO *recordingKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(_ context.Context, cgroupIDs []uint64) error {
	if kernelIO.deleteTrackedErr != nil {
		return kernelIO.deleteTrackedErr
	}
	kernelIO.deleteTracked = append(kernelIO.deleteTracked, cgroupIDs...)
	return nil
}

func (kernelIO *recordingKernelIO) PutCgroupBasenameInStagingMap(_ context.Context, basename string, netBlockSlot uint32) error {
	if kernelIO.putStagingErr != nil {
		return kernelIO.putStagingErr
	}
	kernelIO.putStaging = append(kernelIO.putStaging, basename)
	kernelIO.putStagingSlots = append(kernelIO.putStagingSlots, netBlockSlot)
	return nil
}

func (kernelIO *recordingKernelIO) DeleteCgroupBasenamesFromStagingMap(_ context.Context, basenames []string) error {
	if kernelIO.deleteStagingErr != nil {
		return kernelIO.deleteStagingErr
	}
	kernelIO.deleteStaging = append(kernelIO.deleteStaging, basenames...)
	return nil
}

func (kernelIO *recordingKernelIO) QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64) {
	_ = activeCgroupIDs
}

func (kernelIO *recordingKernelIO) Close() error {
	return kernelIO.closeErr
}

func newTestKernelTracker(logger *slog.Logger, notifier JobEndNotifier, kernelIO kernelio.KernelIO, cgroupV2RootPath string) *KernelTracker {
	if logger == nil {
		logger = slog.Default()
	}
	engine := &KernelTracker{
		logger:           logger.With("component", "kernel_tracker"),
		jobEndNotifier:   notifier,
		kernelIO:         kernelIO,
		cgroupV2RootPath: cgroupV2RootPath,
		inputCh:          make(chan engineInput, defaultEngineInputBufferSize),
	}
	engine.jobTracking = newJobTrackingState()
	engine.jobTracking.logger = engine.logger
	return engine
}

func runTestEffects(t *testing.T, state *jobTrackingState, effects []engineEffect) *recordingKernelIO {
	t.Helper()
	kernelIO := &recordingKernelIO{}
	engine := newTestKernelTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, kernelIO, "")
	engine.jobTracking = state
	engine.runEngineEffects(context.Background(), effects)
	return kernelIO
}
