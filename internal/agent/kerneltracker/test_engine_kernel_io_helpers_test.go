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

func (noopKernelIO) InstallNetBlockProgram(context.Context, uint32, netblock.Program) error {
	return nil
}

func (noopKernelIO) DeleteNetBlockProgram(context.Context, uint32) error {
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
	deleteProgramErr error

	startCalls    int
	putTracked    []uint64
	deleteTracked []uint64
	putStaging    []string
	deleteStaging []string
	// putTrackedTokens and putStagingTokens are parallel to putTracked / putStaging.
	putTrackedTokens []uint32
	putStagingTokens []uint32
	installs         []netBlockInstall
	deletedPrograms  []uint32
}

type netBlockInstall struct {
	token   uint32
	program netblock.Program
}

func (kernelIO *recordingKernelIO) InstallNetBlockProgram(_ context.Context, token uint32, program netblock.Program) error {
	if kernelIO.installErr != nil {
		return kernelIO.installErr
	}
	kernelIO.installs = append(kernelIO.installs, netBlockInstall{token: token, program: program})
	return nil
}

func (kernelIO *recordingKernelIO) DeleteNetBlockProgram(_ context.Context, token uint32) error {
	if kernelIO.deleteProgramErr != nil {
		return kernelIO.deleteProgramErr
	}
	kernelIO.deletedPrograms = append(kernelIO.deletedPrograms, token)
	return nil
}

func (kernelIO *recordingKernelIO) StartKernelSampleLoop(context.Context, kernelio.KernelSampleHandler) error {
	kernelIO.startCalls++
	if kernelIO.startErr != nil {
		return kernelIO.startErr
	}
	return kernelio.ErrNotSupported
}

func (kernelIO *recordingKernelIO) PutCgroupIDInTrackedCgroupsMap(_ context.Context, cgroupID uint64, netBlockToken uint32) error {
	if kernelIO.putTrackedErr != nil {
		return kernelIO.putTrackedErr
	}
	kernelIO.putTracked = append(kernelIO.putTracked, cgroupID)
	kernelIO.putTrackedTokens = append(kernelIO.putTrackedTokens, netBlockToken)
	return nil
}

func (kernelIO *recordingKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(_ context.Context, cgroupIDs []uint64) error {
	if kernelIO.deleteTrackedErr != nil {
		return kernelIO.deleteTrackedErr
	}
	kernelIO.deleteTracked = append(kernelIO.deleteTracked, cgroupIDs...)
	return nil
}

func (kernelIO *recordingKernelIO) PutCgroupBasenameInStagingMap(_ context.Context, basename string, netBlockToken uint32) error {
	if kernelIO.putStagingErr != nil {
		return kernelIO.putStagingErr
	}
	kernelIO.putStaging = append(kernelIO.putStaging, basename)
	kernelIO.putStagingTokens = append(kernelIO.putStagingTokens, netBlockToken)
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
