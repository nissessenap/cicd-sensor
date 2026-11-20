package kerneltracker

import (
	"errors"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// ErrNetBlockUnavailable reports that a Job cannot hold a network block
// program because blocking is disabled.
var ErrNetBlockUnavailable = errors.New("network block is not available for this job")

// netBlockTokens gives each registered Job the key its block program is
// stored under. The token is written into tracked_cgroups from the Job's
// first cgroup, so a program installed later applies to every cgroup at once
// without touching tracking entries. It is opaque to the kernel; which Job
// owns it is known only here. A nil *netBlockTokens means blocking is
// disabled.
type netBlockTokens struct {
	byJob map[jobcontext.JobIdentity]uint32
	// next is never reset: a token that was handed out is not reused, so a
	// tracking entry the kernel still holds for a removed Job can never
	// select a later Job's program.
	next uint32
}

func newNetBlockTokens() *netBlockTokens {
	return &netBlockTokens{byJob: make(map[jobcontext.JobIdentity]uint32)}
}

func (t *netBlockTokens) assign(jobID jobcontext.JobIdentity) {
	if t == nil || t.byJob[jobID] != 0 {
		return
	}
	t.next++
	t.byJob[jobID] = t.next
}

func (t *netBlockTokens) release(jobID jobcontext.JobIdentity) {
	if t != nil {
		delete(t.byJob, jobID)
	}
}

// tokenFor returns the Job's token, or 0 when it has none.
func (t *netBlockTokens) tokenFor(jobID jobcontext.JobIdentity) uint32 {
	if t == nil {
		return 0
	}
	return t.byJob[jobID]
}

func handleSetNetBlockProgram(state *jobTrackingState, command commandSetNetBlockProgram) []engineEffect {
	var err error
	if _, registered := state.jobs[command.JobID]; !registered {
		err = fmt.Errorf("set network block program: job not registered")
	} else if state.netBlock.tokenFor(command.JobID) == 0 {
		err = ErrNetBlockUnavailable
	}
	if err != nil {
		return []engineEffect{replySetNetBlockProgram{Reply: command.Reply, Err: err}}
	}
	return []engineEffect{installNetBlockProgram(command)}
}
