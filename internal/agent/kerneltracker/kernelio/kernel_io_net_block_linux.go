//go:build linux

package kernelio

import (
	"context"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cilium/ebpf"
)

func (kernelIO *LinuxKernelIO) InstallNetBlockProgram(ctx context.Context, slot uint32, buffer uint32, program netblock.Program) error {
	_ = ctx
	if slot == 0 || (buffer != 1 && buffer != 2) {
		return fmt.Errorf("install network block program: invalid slot %d buffer %d", slot, buffer)
	}
	value, err := encodeNetBlockProgram(program)
	if err != nil {
		return err
	}
	// Order matters: hooks must only see the buffer once it is complete.
	if err := kernelIO.objs.NetBlockPrograms.Update(slot*2+buffer-1, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put network block program for slot %d: %w", slot, err)
	}
	if err := kernelIO.objs.NetBlockActive.Update(slot, buffer, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("activate network block program for slot %d: %w", slot, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) ClearNetBlockSlot(ctx context.Context, slot uint32) error {
	_ = ctx
	if slot == 0 {
		return nil
	}
	if err := kernelIO.objs.NetBlockActive.Update(slot, uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear network block slot %d: %w", slot, err)
	}
	return nil
}

func encodeNetBlockProgram(program netblock.Program) (*bpfprog.BPFProgramNetBlockProgram, error) {
	if err := program.Validate(); err != nil {
		return nil, err
	}
	value := &bpfprog.BPFProgramNetBlockProgram{InsnCount: uint32(len(program))}
	for i, insn := range program {
		encoded := &value.Insns[i]
		encoded.Truth = insn.Truth
		encoded.Pop = insn.Pop
		// The kernel compares addresses as 32-bit words in memory order, so
		// the bytes must land unchanged regardless of host endianness.
		for word := range encoded.Value.Addr {
			encoded.Value.Addr[word] = binary.NativeEndian.Uint32(insn.Value.Addr[word*4:])
			encoded.Mask.Addr[word] = binary.NativeEndian.Uint32(insn.Mask.Addr[word*4:])
		}
		encoded.Value.Port = insn.Value.Port
		encoded.Value.Protocol = insn.Value.Proto
		encoded.Mask.Port = insn.Mask.Port
		encoded.Mask.Protocol = insn.Mask.Proto
	}
	return value, nil
}

// TestOnlyRingbufDropCount reports how many samples were dropped because the
// events ring buffer was full.
func (kernelIO *LinuxKernelIO) TestOnlyRingbufDropCount() (uint64, error) {
	return kernelIO.readRingbufDropCount()
}
