package celengine

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func blockRule(condition, exceptions string, clauses ...string) rule.ResolvedRule {
	resolved := rule.ResolvedRule{
		Rule: rule.Rule{
			RuleID:     "r",
			EventType:  jobevent.NetworkConnect,
			Condition:  condition,
			Exceptions: exceptions,
			Action:     rule.RuleActionBlock,
		},
	}
	for _, clause := range clauses {
		resolved.ExceptionClauses = append(resolved.ExceptionClauses, rule.ResolvedExceptionClause{Source: clause, ModifierIdentity: "m"})
	}
	return resolved
}

func dest(t *testing.T, ip string, port uint16, proto uint8) netblock.Tuple {
	t.Helper()
	return netblock.Tuple{Addr: netip.MustParseAddr(ip).As16(), Port: port, Proto: proto}
}

func TestLowerNetBlockRuleDecisions(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}

	type probe struct {
		ip    string
		port  uint16
		proto uint8
		want  bool
	}
	tests := []struct {
		name       string
		condition  string
		exceptions string
		clauses    []string
		probes     []probe
	}{
		{
			name:      "exact IPv4 address blocks only that address",
			condition: `remote_ip == "169.254.169.254"`,
			probes: []probe{
				{"169.254.169.254", 80, netblock.ProtoTCP, true},
				{"169.254.169.253", 80, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "IPv4-mapped destination is the same IPv4 address",
			condition: `"192.0.2.1" == remote_ip`,
			probes: []probe{
				{"::ffff:192.0.2.1", 443, netblock.ProtoTCP, true},
				{"::ffff:192.0.2.2", 443, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "uppercase IPv6 literal is normalized like CEL literals",
			condition: `remote_ip == "2001:DB8::1"`,
			probes: []probe{
				{"2001:db8::1", 443, netblock.ProtoTCP, true},
				{"2001:db8::2", 443, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "CIDR boundary is inclusive of the network and exclusive past it",
			condition: `inIpRange(remote_ip, "10.20.0.0/23")`,
			probes: []probe{
				{"10.20.0.0", 1, netblock.ProtoTCP, true},
				{"10.20.1.255", 1, netblock.ProtoTCP, true},
				{"10.20.2.0", 1, netblock.ProtoTCP, false},
				{"10.19.255.255", 1, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "unmasked CIDR base is masked like net.ParseCIDR",
			condition: `inIpRange(remote_ip, "10.1.2.3/8")`,
			probes: []probe{
				{"10.255.0.1", 1, netblock.ProtoTCP, true},
				{"11.0.0.1", 1, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "IPv4 catch-all never matches IPv6",
			condition: `inIpRange(remote_ip, "0.0.0.0/0")`,
			probes: []probe{
				{"8.8.8.8", 53, netblock.ProtoUDP, true},
				{"2001:db8::1", 53, netblock.ProtoUDP, false},
			},
		},
		{
			name:      "IPv6 catch-all never matches IPv4",
			condition: `inIpRange(remote_ip, "::/0")`,
			probes: []probe{
				{"2001:db8::1", 53, netblock.ProtoUDP, true},
				{"8.8.8.8", 53, netblock.ProtoUDP, false},
				{"::ffff:8.8.8.8", 53, netblock.ProtoUDP, false},
			},
		},
		{
			name:      "default deny blocks everything outside the allow list",
			condition: `!(inIpRange(remote_ip, "10.20.0.0/24") || inIpRange(remote_ip, "192.0.2.0/24"))`,
			probes: []probe{
				{"10.20.0.9", 443, netblock.ProtoTCP, false},
				{"192.0.2.9", 443, netblock.ProtoTCP, false},
				{"198.51.100.1", 443, netblock.ProtoTCP, true},
				{"2001:db8::1", 443, netblock.ProtoTCP, true},
			},
		},
		{
			name:      "port and protocol narrow the match",
			condition: `remote_ip == "192.0.2.1" && remote_port == 443 && protocol == "TCP"`,
			probes: []probe{
				{"192.0.2.1", 443, netblock.ProtoTCP, true},
				{"192.0.2.1", 443, netblock.ProtoUDP, false},
				{"192.0.2.1", 80, netblock.ProtoTCP, false},
			},
		},
		{
			name:      "family follows the destination, not the socket",
			condition: `family == "ipv6" && remote_port == 53`,
			probes: []probe{
				{"2001:db8::1", 53, netblock.ProtoUDP, true},
				{"::ffff:192.0.2.1", 53, netblock.ProtoUDP, false},
				{"192.0.2.1", 53, netblock.ProtoUDP, false},
			},
		},
		{
			name:       "base exception and modifier exceptions each carve out",
			condition:  `inIpRange(remote_ip, "10.0.0.0/8")`,
			exceptions: `inIpRange(remote_ip, "10.20.0.0/24") && remote_port == 443`,
			clauses:    []string{`remote_ip == "10.9.9.9"`},
			probes: []probe{
				{"10.1.1.1", 443, netblock.ProtoTCP, true},
				{"10.20.0.5", 443, netblock.ProtoTCP, false},
				{"10.20.0.5", 80, netblock.ProtoTCP, true},
				{"10.9.9.9", 80, netblock.ProtoTCP, false},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program, err := env.LowerNetBlockRule(blockRule(tc.condition, tc.exceptions, tc.clauses...))
			if err != nil {
				t.Fatalf("LowerNetBlockRule: %v", err)
			}
			if err := program.Validate(); err != nil {
				t.Fatalf("lowered program is invalid: %v", err)
			}
			for _, p := range tc.probes {
				if got := program.Eval(dest(t, p.ip, p.port, p.proto)); got != p.want {
					t.Errorf("Eval(%s:%d proto %d) = %v, want %v", p.ip, p.port, p.proto, got, p.want)
				}
			}
		})
	}
}

func TestLowerNetBlockRuleRejectsIncompatibleConditions(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}

	tests := []struct {
		name       string
		condition  string
		exceptions string
		clauses    []string
		wantField  string
	}{
		{name: "process context is userspace only", condition: `remote_ip == "192.0.2.1" && process.exec_path.endsWith("/curl")`, wantField: "process.exec_path"},
		{name: "process argv comprehension is userspace only", condition: `process.argv.exists(a, a == "x")`, wantField: "process.argv"},
		{name: "process field as the compared value", condition: `remote_ip == process.exec_path`, wantField: "process.exec_path"},
		{name: "predefined lists are out of scope", condition: `remote_ip in list.blocked`, wantField: "list.blocked"},
		{name: "list-driven CIDR is out of scope", condition: `list.cidrs.exists(c, inIpRange(remote_ip, c))`, wantField: "list.cidrs"},
		{name: "string function on a destination field", condition: `remote_ip.startsWith("10.")`, wantField: "startsWith"},
		{name: "inequality must be written with negation", condition: `remote_port != 443`, wantField: "!="},
		{name: "ordering is not evaluable in the kernel form", condition: `remote_port < 1024`, wantField: "<"},
		{name: "two fields compared", condition: `remote_ip == family`, wantField: "remote_ip"},
		{name: "constant condition", condition: `true`, wantField: "true"},
		{name: "non-canonical IPv6 spelling can never match in CEL", condition: `remote_ip == "2001:db8:0:0:0:0:0:1"`, wantField: "remote_ip"},
		{name: "IPv4-mapped literal can never match in CEL", condition: `remote_ip == "::ffff:192.0.2.1"`, wantField: "remote_ip"},
		{name: "hostname is not an address", condition: `remote_ip == "example.com"`, wantField: "remote_ip"},
		{name: "port zero is never reported", condition: `remote_port == 0`, wantField: "remote_port"},
		{name: "port above the 16-bit range", condition: `remote_port == 65536`, wantField: "remote_port"},
		{name: "unknown protocol can never match", condition: `protocol == "icmp"`, wantField: "protocol"},
		{name: "unknown family can never match", condition: `family == "inet"`, wantField: "family"},
		{name: "IPv4-mapped CIDR", condition: `inIpRange(remote_ip, "::ffff:10.0.0.0/104")`, wantField: "inIpRange"},
		{name: "constant inIpRange subject", condition: `inIpRange("10.0.0.1", "10.0.0.0/8")`, wantField: "inIpRange"},
		{name: "incompatible base exception", condition: `remote_ip == "192.0.2.1"`, exceptions: `process.exec_path == "/usr/bin/apt"`, wantField: "process.exec_path"},
		{name: "incompatible modifier exception", condition: `remote_ip == "192.0.2.1"`, clauses: []string{`process.exec_path == "/usr/bin/apt"`}, wantField: "process.exec_path"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := env.LowerNetBlockRule(blockRule(tc.condition, tc.exceptions, tc.clauses...))
			var conditionErr *BlockConditionError
			if !errors.As(err, &conditionErr) {
				t.Fatalf("error = %v, want *BlockConditionError", err)
			}
			if conditionErr.Field != tc.wantField {
				t.Fatalf("Field = %q, want %q (error: %v)", conditionErr.Field, tc.wantField, err)
			}
		})
	}
}

func TestLowerNetBlockRuleReturnsCompileErrors(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}

	tests := []struct {
		name       string
		condition  string
		exceptions string
	}{
		{name: "syntax error in condition", condition: `remote_ip ==`},
		{name: "type error in condition", condition: `remote_port == "443"`},
		{name: "unsigned port literal does not type-check against int", condition: `remote_port == 443u`},
		{name: "invalid CIDR literal", condition: `inIpRange(remote_ip, "10.0.0.0/33")`},
		{name: "syntax error in exception", condition: `remote_port == 443`, exceptions: `&&`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := env.LowerNetBlockRule(blockRule(tc.condition, tc.exceptions))
			if err == nil {
				t.Fatal("expected a compile error")
			}
			var conditionErr *BlockConditionError
			if errors.As(err, &conditionErr) {
				t.Fatalf("compile failure reported as block incompatibility: %v", err)
			}
		})
	}
}
