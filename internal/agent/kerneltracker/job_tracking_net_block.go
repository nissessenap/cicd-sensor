package kerneltracker

import (
	"errors"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

// defaultNetBlockSlots bounds how many concurrent Jobs can be enforced. Each
// slot preallocates two program buffers in the kernel (about 6 KiB).
const defaultNetBlockSlots = 1024

// ErrNetBlockUnavailable reports that a Job has no network block slot, either
// because blocking is disabled or because every slot is in use.
var ErrNetBlockUnavailable = errors.New("network block is not available for this job")

// jobNetBlock is one Job's kernel block state. The slot is opaque to the
// kernel; which Job owns it is known only here.
type jobNetBlock struct {
	slot uint32
	// activeBuffer is the program buffer the hooks evaluate: 0 before the
	// first install, then 1 or 2.
	activeBuffer uint32
}

// netBlockSlots assigns each registered Job a slot for its whole lifetime.
// The slot is written into tracked_cgroups from the Job's first cgroup, so a
// program installed later applies to every cgroup at once without touching
// tracking entries. A nil *netBlockSlots means blocking is disabled.
type netBlockSlots struct {
	byJob map[jobcontext.JobIdentity]*jobNetBlock
	inUse map[uint32]struct{}
	limit uint32
	// last is where the next search starts. Rotating keeps a just-released
	// slot idle for as long as possible before it is handed out again.
	last uint32
}

func newNetBlockSlots(limit uint32) *netBlockSlots {
	return &netBlockSlots{
		byJob: make(map[jobcontext.JobIdentity]*jobNetBlock),
		inUse: make(map[uint32]struct{}),
		limit: limit,
	}
}

// allocate gives jobID a slot if one is free. A Job left without a slot is
// still tracked; only a later program install for it fails.
func (s *netBlockSlots) allocate(jobID jobcontext.JobIdentity) {
	if s == nil || s.byJob[jobID] != nil {
		return
	}
	for range s.limit {
		s.last = s.last%s.limit + 1
		if _, used := s.inUse[s.last]; used {
			continue
		}
		s.inUse[s.last] = struct{}{}
		s.byJob[jobID] = &jobNetBlock{slot: s.last}
		return
	}
}

func (s *netBlockSlots) release(jobID jobcontext.JobIdentity) {
	if s == nil {
		return
	}
	if state := s.byJob[jobID]; state != nil {
		delete(s.inUse, state.slot)
		delete(s.byJob, jobID)
	}
}

// slotFor returns the Job's slot, or 0 when it has none.
func (s *netBlockSlots) slotFor(jobID jobcontext.JobIdentity) uint32 {
	if s == nil {
		return 0
	}
	if state := s.byJob[jobID]; state != nil {
		return state.slot
	}
	return 0
}

func handleSetNetBlockProgram(state *jobTrackingState, command commandSetNetBlockProgram) []engineEffect {
	var err error
	if _, registered := state.jobs[command.JobID]; !registered {
		err = fmt.Errorf("set network block program: job not registered")
	} else if state.netBlock.slotFor(command.JobID) == 0 {
		err = ErrNetBlockUnavailable
	} else if validateErr := command.Program.Validate(); validateErr != nil {
		err = validateErr
	} else if len(command.Program) == 0 {
		err = fmt.Errorf("set network block program: %w: empty program", netblock.ErrMalformedProgram)
	}
	if err != nil {
		return []engineEffect{replySetNetBlockProgram{Reply: command.Reply, Err: err}}
	}
	return []engineEffect{installNetBlockProgram(command)}
}
