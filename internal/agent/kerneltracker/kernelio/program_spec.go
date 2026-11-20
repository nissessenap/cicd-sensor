package kernelio

import (
	"fmt"
	"math"
	"math/bits"
	"runtime"

	"github.com/cilium/ebpf"
)

const (
	eventsMapName           = "events"
	netBlockActiveMapName   = "net_block_active"
	netBlockProgramsMapName = "net_block_programs"
	// Keep at least 8 MiB for small CI/CD runner nodes.
	minEventsRingbufMaxEntries = 8 << 20
	// Add 4 MiB per CPU so larger runner nodes get more ingress capacity.
	eventsRingbufMaxBytesPerCPU = 4 << 20
)

// configureBPFProgramSpec applies userspace-owned map settings before load.
func configureBPFProgramSpec(spec *ebpf.CollectionSpec, netBlockSlots uint32) error {
	eventsMap := spec.Maps[eventsMapName]
	if eventsMap == nil {
		return fmt.Errorf("bpf map %q not found", eventsMapName)
	}
	eventsMaxEntries, err := eventsRingbufMaxEntries(runtime.NumCPU())
	if err != nil {
		return err
	}
	eventsMap.MaxEntries = eventsMaxEntries

	stagingMap := spec.Maps[StagingMapName]
	if stagingMap == nil {
		return fmt.Errorf("bpf map %q not found", StagingMapName)
	}
	stagingMap.MaxEntries = StagingMaxEntries

	netBlockActive := spec.Maps[netBlockActiveMapName]
	if netBlockActive == nil {
		return fmt.Errorf("bpf map %q not found", netBlockActiveMapName)
	}
	netBlockPrograms := spec.Maps[netBlockProgramsMapName]
	if netBlockPrograms == nil {
		return fmt.Errorf("bpf map %q not found", netBlockProgramsMapName)
	}
	// Slot 0 means "no slot", so usable slots are 1..netBlockSlots, and each
	// slot owns two program buffers at index slot*2 and slot*2+1.
	netBlockActive.MaxEntries = netBlockSlots + 1
	netBlockPrograms.MaxEntries = (netBlockSlots + 1) * 2

	return nil
}

func eventsRingbufMaxEntries(cpuCount int) (uint32, error) {
	if cpuCount <= 0 {
		return 0, fmt.Errorf("cpu count must be positive, got %d", cpuCount)
	}

	size := uint64(cpuCount) * eventsRingbufMaxBytesPerCPU
	size = max(size, minEventsRingbufMaxEntries)

	// BPF_MAP_TYPE_RINGBUF requires max_entries to be a power of two.
	rounded := roundUpToPowerOfTwo(size)
	if rounded > math.MaxUint32 {
		return 0, fmt.Errorf("events ringbuf max entries %d exceed uint32", rounded)
	}
	return uint32(rounded), nil
}

func roundUpToPowerOfTwo(value uint64) uint64 {
	if value <= 1 {
		return 1
	}
	return 1 << bits.Len64(value-1)
}
