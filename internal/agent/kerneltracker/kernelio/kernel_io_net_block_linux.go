//go:build linux

package kernelio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cilium/ebpf"
)

func (kernelIO *LinuxKernelIO) InstallNetBlockProgram(ctx context.Context, token uint32, program netblock.Program) error {
	_ = ctx
	if token == 0 {
		return fmt.Errorf("install network block program: token 0 is reserved")
	}
	value, err := encodeNetBlockProgram(program)
	if err != nil {
		return err
	}
	if err := kernelIO.objs.NetBlockPrograms.Update(token, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put network block program for token %d: %w", token, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteNetBlockProgram(ctx context.Context, token uint32) error {
	_ = ctx
	if token == 0 {
		return nil
	}
	if err := kernelIO.objs.NetBlockPrograms.Delete(token); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete network block program for token %d: %w", token, err)
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
