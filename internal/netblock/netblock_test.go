package netblock

import (
	"errors"
	"slices"
	"testing"
)

var (
	matchAll  = Match(Tuple{}, Tuple{})
	matchNone = Match(Tuple{Proto: 0xff}, Tuple{Proto: 0xff})
)

func TestProgramEvalBooleanOperators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		program Program
		want    bool
	}{
		{name: "empty program blocks nothing", program: nil, want: false},
		{name: "match pushes true", program: Program{matchAll}, want: true},
		{name: "match pushes false", program: Program{matchNone}, want: false},
		{name: "not true", program: Program{matchAll, Not()}, want: false},
		{name: "not false", program: Program{matchNone, Not()}, want: true},
		{name: "true and true", program: Program{matchAll, matchAll, And()}, want: true},
		{name: "true and false", program: Program{matchAll, matchNone, And()}, want: false},
		{name: "false and true", program: Program{matchNone, matchAll, And()}, want: false},
		{name: "false and false", program: Program{matchNone, matchNone, And()}, want: false},
		{name: "true or true", program: Program{matchAll, matchAll, Or()}, want: true},
		{name: "true or false", program: Program{matchAll, matchNone, Or()}, want: true},
		{name: "false or true", program: Program{matchNone, matchAll, Or()}, want: true},
		{name: "false or false", program: Program{matchNone, matchNone, Or()}, want: false},
		{
			name:    "binary operator leaves deeper entries untouched",
			program: Program{matchAll, matchNone, matchNone, Or(), Or()},
			want:    true,
		},
		{
			name:    "unary operator leaves deeper entries untouched",
			program: Program{matchNone, matchAll, Not(), Or()},
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.program.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := tc.program.Eval(Tuple{Port: 443, Proto: ProtoTCP}); got != tc.want {
				t.Fatalf("Eval = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProgramEvalMaskedCompare(t *testing.T) {
	t.Parallel()

	dst := Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 7}, Port: 443, Proto: ProtoTCP}
	fullAddr := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	tests := []struct {
		name  string
		value Tuple
		mask  Tuple
		want  bool
	}{
		{name: "zero mask ignores every field", value: Tuple{Port: 1, Proto: 1}, mask: Tuple{}, want: true},
		{name: "full address match", value: Tuple{Addr: dst.Addr}, mask: Tuple{Addr: fullAddr}, want: true},
		{name: "last address byte differs", value: Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 8}}, mask: Tuple{Addr: fullAddr}, want: false},
		{name: "first address byte differs", value: Tuple{Addr: [16]byte{0: 1, 10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 7}}, mask: Tuple{Addr: fullAddr}, want: false},
		{name: "masked-out address bits are ignored", value: Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 0}}, mask: Tuple{Addr: [16]byte{10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff}}, want: true},
		{name: "port equal", value: Tuple{Port: 443}, mask: Tuple{Port: 0xffff}, want: true},
		{name: "port differs in the high byte", value: Tuple{Port: 443 + 256}, mask: Tuple{Port: 0xffff}, want: false},
		{name: "protocol equal", value: Tuple{Proto: ProtoTCP}, mask: Tuple{Proto: 0xff}, want: true},
		{name: "protocol differs", value: Tuple{Proto: ProtoUDP}, mask: Tuple{Proto: 0xff}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := (Program{Match(tc.value, tc.mask)}).Eval(dst); got != tc.want {
				t.Fatalf("Eval = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProgramValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		program Program
		wantErr error
	}{
		{name: "empty program is valid", program: nil},
		{name: "single match", program: Program{matchAll}},
		{name: "exactly at the instruction limit", program: slices.Concat(Program{matchAll}, slices.Repeat(Program{Not()}, MaxInsns-1))},
		{name: "one over the instruction limit", program: slices.Concat(Program{matchAll}, slices.Repeat(Program{Not()}, MaxInsns)), wantErr: ErrProgramTooLarge},
		{name: "not on an empty stack", program: Program{Not()}, wantErr: ErrMalformedProgram},
		{name: "binary operator with one operand", program: Program{matchAll, And()}, wantErr: ErrMalformedProgram},
		{name: "two results left on the stack", program: Program{matchAll, matchAll}, wantErr: ErrMalformedProgram},
		{name: "pop count outside the encoding", program: Program{matchAll, matchAll, matchAll, {Pop: 3}}, wantErr: ErrMalformedProgram},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.program.Validate()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestUnion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		programs []Program
		want     bool
		wantLen  int
		wantErr  error
	}{
		{name: "no programs yields the empty program", programs: nil, want: false, wantLen: 0},
		{name: "empty programs are skipped", programs: []Program{nil, {matchNone}, nil}, want: false, wantLen: 1},
		{name: "any matching program blocks", programs: []Program{{matchNone}, {matchAll}, {matchNone}}, want: true, wantLen: 5},
		{name: "no matching program allows", programs: []Program{{matchNone}, {matchNone}}, want: false, wantLen: 3},
		{name: "malformed member is rejected", programs: []Program{{matchAll}, {And()}}, wantErr: ErrMalformedProgram},
		{
			name:     "union over the instruction limit is rejected",
			programs: slices.Repeat([]Program{{matchAll}}, MaxInsns/2+1),
			wantErr:  ErrProgramTooLarge,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Union(tc.programs...)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Union error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
			if eval := got.Eval(Tuple{}); eval != tc.want {
				t.Fatalf("Eval = %v, want %v", eval, tc.want)
			}
		})
	}
}
