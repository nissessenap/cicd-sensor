// Package netblock defines the kernel-evaluable form of network block rules
// and the Go reference evaluator for it.
//
// CEL stays the semantic definition of a block rule. A Program is an
// equivalent projection of destination-only conditions that the
// cgroup/connect hooks can evaluate without userspace: a postfix boolean
// expression over masked compares of the connect destination.
package netblock

import (
	"errors"
	"fmt"
)

// MaxInsns bounds one Job's Program. It must match NET_BLOCK_MAX_INSNS in
// internal/agent/bpf/maps.bpf.h, which sizes the verifier-bounded loop.
const MaxInsns = 64

// Protocol numbers the connect hooks evaluate.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// ErrProgramTooLarge reports a Program that exceeds MaxInsns.
var ErrProgramTooLarge = errors.New("network block program too large")

// ErrMalformedProgram reports a Program that is not one well-formed postfix
// expression.
var ErrMalformedProgram = errors.New("malformed network block program")

// Tuple is a connect destination, or a value / mask over one.
type Tuple struct {
	// Addr is the destination in network byte order. IPv4 destinations are
	// stored IPv4-mapped (::ffff:a.b.c.d), matching how the Agent reports an
	// IPv4-mapped IPv6 connect as family "ipv4".
	Addr  [16]byte
	Port  uint16
	Proto uint8
}

// Insn is one postfix instruction. It pops Pop entries off the boolean stack
// and pushes one result, looked up in Truth.
//
// The encoding is arithmetic on purpose: the kernel evaluates it without a
// data-dependent branch, which keeps the verifier on a single path through
// the evaluation loop.
type Insn struct {
	// Value and Mask describe the destination compare. An all-zero Mask
	// matches every destination.
	Value Tuple
	Mask  Tuple
	// Truth bit (match<<2 | second<<1 | top) is the result, where match is
	// the destination compare and top / second are the stack entries.
	Truth uint8
	// Pop is how many stack entries the instruction consumes: 0, 1 or 2.
	Pop uint8
}

// Match pushes whether the destination equals value under mask.
func Match(value, mask Tuple) Insn {
	return Insn{Value: value, Mask: mask, Truth: 0b1111_0000}
}

// Not negates the top of the stack.
func Not() Insn { return Insn{Truth: 0b0101_0101, Pop: 1} }

// And replaces the top two stack entries with their conjunction.
func And() Insn { return Insn{Truth: 0b1000_1000, Pop: 2} }

// Or replaces the top two stack entries with their disjunction.
func Or() Insn { return Insn{Truth: 0b1110_1110, Pop: 2} }

// Program is a postfix boolean expression. The empty Program matches nothing.
type Program []Insn

// Eval reports whether the Program blocks dst. It mirrors
// net_block_matches in internal/agent/bpf/network_hooks.bpf.h step for step,
// including the 64-entry bit stack, so the two can be compared.
func (p Program) Eval(dst Tuple) bool {
	var stack uint64
	for _, insn := range p {
		var match uint64
		if insn.matches(dst) {
			match = 1
		}
		index := stack&3 | match<<2
		result := uint64(insn.Truth>>index) & 1
		stack = stack>>(insn.Pop&3)<<1 | result
	}
	return stack&1 == 1
}

func (insn Insn) matches(dst Tuple) bool {
	for i := range dst.Addr {
		if (dst.Addr[i]^insn.Value.Addr[i])&insn.Mask.Addr[i] != 0 {
			return false
		}
	}
	return (dst.Port^insn.Value.Port)&insn.Mask.Port == 0 &&
		(dst.Proto^insn.Value.Proto)&insn.Mask.Proto == 0
}

// Validate checks that the Program fits the kernel bounds and leaves exactly
// one result on the stack. The kernel evaluator does not re-check this.
func (p Program) Validate() error {
	if len(p) > MaxInsns {
		return fmt.Errorf("%w: %d instructions, limit %d", ErrProgramTooLarge, len(p), MaxInsns)
	}
	if len(p) == 0 {
		return nil
	}
	depth := 0
	for i, insn := range p {
		if insn.Pop > 2 {
			return fmt.Errorf("%w: instruction %d pops %d entries", ErrMalformedProgram, i, insn.Pop)
		}
		if depth < int(insn.Pop) {
			return fmt.Errorf("%w: instruction %d needs %d operands, stack has %d", ErrMalformedProgram, i, insn.Pop, depth)
		}
		depth += 1 - int(insn.Pop)
	}
	if depth != 1 {
		return fmt.Errorf("%w: leaves %d results", ErrMalformedProgram, depth)
	}
	return nil
}

// Union returns a Program that matches when any of the given programs
// matches. Empty programs are skipped.
func Union(programs ...Program) (Program, error) {
	var out Program
	for _, program := range programs {
		if len(program) == 0 {
			continue
		}
		joined := len(out) > 0
		out = append(out, program...)
		if joined {
			out = append(out, Or())
		}
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}
