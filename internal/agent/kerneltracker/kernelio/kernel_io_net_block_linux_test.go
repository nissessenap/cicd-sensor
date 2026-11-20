//go:build linux

package kernelio

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

func TestEncodeNetBlockProgram(t *testing.T) {
	t.Parallel()

	match := netblock.Match(
		netblock.Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 1}, Port: 443, Proto: netblock.ProtoTCP},
		netblock.Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}, Port: 0xffff, Proto: 0xff},
	)
	encoded, err := encodeNetBlockProgram(netblock.Program{match, netblock.Not()})
	if err != nil {
		t.Fatalf("encodeNetBlockProgram: %v", err)
	}

	if encoded.InsnCount != 2 {
		t.Fatalf("InsnCount = %d, want 2", encoded.InsnCount)
	}
	first := encoded.Insns[0]
	// The kernel reads address words in memory order, so the bytes of the
	// last word must come back out as written.
	var lastWord [4]byte
	binary.NativeEndian.PutUint32(lastWord[:], first.Value.Addr[3])
	if lastWord != [4]byte{192, 0, 2, 1} {
		t.Fatalf("value address word 3 bytes = %v, want [192 0 2 1]", lastWord)
	}
	binary.NativeEndian.PutUint32(lastWord[:], first.Mask.Addr[2])
	if lastWord != [4]byte{0, 0, 0xff, 0xff} {
		t.Fatalf("mask address word 2 bytes = %v, want [0 0 255 255]", lastWord)
	}
	if first.Value.Port != 443 || first.Mask.Port != 0xffff {
		t.Fatalf("port value/mask = %d/%#x, want 443/0xffff", first.Value.Port, first.Mask.Port)
	}
	if first.Value.Protocol != netblock.ProtoTCP || first.Mask.Protocol != 0xff {
		t.Fatalf("protocol value/mask = %d/%#x, want 6/0xff", first.Value.Protocol, first.Mask.Protocol)
	}
	if first.Truth != match.Truth || first.Pop != 0 {
		t.Fatalf("match truth/pop = %#x/%d, want %#x/0", first.Truth, first.Pop, match.Truth)
	}
	if second := encoded.Insns[1]; second.Truth != netblock.Not().Truth || second.Pop != 1 {
		t.Fatalf("not truth/pop = %#x/%d, want %#x/1", second.Truth, second.Pop, netblock.Not().Truth)
	}
	if third := encoded.Insns[2]; third.Truth != 0 || third.Pop != 0 {
		t.Fatalf("instruction past the program is not zero: %+v", third)
	}
}

func TestEncodeNetBlockProgramRejectsInvalidPrograms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		program netblock.Program
		wantErr error
	}{
		{name: "malformed stack discipline", program: netblock.Program{netblock.And()}, wantErr: netblock.ErrMalformedProgram},
		{
			name:    "more instructions than the kernel buffer holds",
			program: slices.Concat(netblock.Program{netblock.Match(netblock.Tuple{}, netblock.Tuple{})}, slices.Repeat(netblock.Program{netblock.Not()}, netblock.MaxInsns)),
			wantErr: netblock.ErrProgramTooLarge,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := encodeNetBlockProgram(tc.program); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestInstallNetBlockProgramRejectsInvalidTarget(t *testing.T) {
	t.Parallel()

	program := netblock.Program{netblock.Match(netblock.Tuple{}, netblock.Tuple{})}
	tests := []struct {
		name   string
		slot   uint32
		buffer uint32
	}{
		{name: "slot zero means no slot", slot: 0, buffer: 1},
		{name: "buffer zero means inactive", slot: 1, buffer: 0},
		{name: "buffer beyond the two per slot", slot: 1, buffer: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kernelIO := &LinuxKernelIO{}
			if err := kernelIO.InstallNetBlockProgram(t.Context(), tc.slot, tc.buffer, program); err == nil {
				t.Fatal("expected an error before any map write")
			}
		})
	}
}

func TestClearNetBlockSlotIgnoresJobsWithoutSlot(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	if err := kernelIO.ClearNetBlockSlot(t.Context(), 0); err != nil {
		t.Fatalf("ClearNetBlockSlot(0) = %v, want nil", err)
	}
}
