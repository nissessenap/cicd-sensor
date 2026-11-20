//go:build linux

package kernelio

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
)

func (kernelIO *LinuxKernelIO) PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64, netBlockSlot uint32) error {
	_ = ctx
	if err := kernelIO.objs.TrackedCgroups.Update(cgroupID, netBlockSlot, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put cgroup id %d in tracked_cgroups map: %w", cgroupID, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error {
	_ = ctx
	for _, cgroupID := range cgroupIDs {
		if err := kernelIO.objs.TrackedCgroups.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete cgroup id %d from tracked_cgroups map: %w", cgroupID, err)
		}
	}
	return nil
}

func (kernelIO *LinuxKernelIO) PutCgroupBasenameInStagingMap(ctx context.Context, basename string, netBlockSlot uint32) error {
	_ = ctx
	key, err := fixedStagingMapKey([]byte(basename))
	if err != nil {
		return err
	}
	value := bpfprog.BPFProgramStagingValue{NetBlockSlot: netBlockSlot}
	if err := kernelIO.objs.StagingMap.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put cgroup basename %q in staging_map: %w", basename, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error {
	_ = ctx
	for _, basename := range basenames {
		key, err := fixedStagingMapKey([]byte(basename))
		if err != nil {
			return err
		}
		// Kernel cgroup_mkdir promotion may have already consumed this entry.
		if err := kernelIO.objs.StagingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete cgroup basename %q from staging_map: %w", basename, err)
		}
	}
	return nil
}

func (kernelIO *LinuxKernelIO) TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) (bool, error) {
	_, tracked, err := kernelIO.TestOnlyLookupNetBlockSlot(ctx, cgroupID)
	return tracked, err
}

// TestOnlyLookupNetBlockSlot returns the network block slot stored with a
// tracked cgroup, and whether the cgroup is tracked at all.
func (kernelIO *LinuxKernelIO) TestOnlyLookupNetBlockSlot(ctx context.Context, cgroupID uint64) (slot uint32, tracked bool, err error) {
	_ = ctx
	err = kernelIO.objs.TrackedCgroups.Lookup(cgroupID, &slot)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("lookup cgroup id %d in tracked_cgroups map: %w", cgroupID, err)
	}
	return slot, true, nil
}

func (kernelIO *LinuxKernelIO) TestOnlyLookupCgroupBasenameInStagingMap(ctx context.Context, basename string) (bool, error) {
	_ = ctx
	key, err := fixedStagingMapKey([]byte(basename))
	if err != nil {
		return false, err
	}
	var value bpfprog.BPFProgramStagingValue
	err = kernelIO.objs.StagingMap.Lookup(key, &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup cgroup basename %q in staging_map: %w", basename, err)
	}
	return true, nil
}

func fixedStagingMapKey(key []byte) ([]byte, error) {
	if len(key) > StagingKeyLen {
		return nil, fmt.Errorf("staging_map key must be at most %d bytes, got %d", StagingKeyLen, len(key))
	}
	if bytes.IndexByte(key, '/') >= 0 {
		return nil, fmt.Errorf("staging_map key must be a cgroup basename, got %q", string(key))
	}
	// staging_map uses char[STAGING_KEY_LEN], so short basenames must be zero-padded.
	fixed := make([]byte, StagingKeyLen)
	copy(fixed, key)
	return fixed, nil
}

// TestOnlyOpenSSLProgram returns the OpenSSL uprobe entry program so
// integration tests can attach it directly to a libssl inode. Not for
// production use — production attaches via OpenSSL uprobe discovery.
func (kernelIO *LinuxKernelIO) TestOnlyOpenSSLProgram() *ebpf.Program {
	return kernelIO.objs.HandleSslWrite
}
