package evaluation

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

func blockRule(id, condition string) rule.Rule {
	return rule.Rule{RuleID: id, EventType: jobevent.NetworkConnect, Condition: condition, Action: rule.RuleActionBlock}
}

func resolvedScope(scope *jobscope.JobScopeState, monitorMode bool, modifiers []rule.RuleModifier, rules ...rule.Rule) *jobscope.JobScopeState {
	scope.RuleSets = []rule.RuleSet{{RulesetID: "egress", Rules: rules}}
	scope.RuleModifiers = modifiers
	scope.MonitorMode = monitorMode
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}

func netBlockDest(ip string, port uint16) netblock.Tuple {
	return netblock.Tuple{Addr: netip.MustParseAddr(ip).As16(), Port: port, Proto: netblock.ProtoTCP}
}

func TestNetBlockProgram(t *testing.T) {
	t.Parallel()

	metadata := blockRule("metadata", `remote_ip == "169.254.169.254"`)
	testNet := blockRule("test_net", `inIpRange(remote_ip, "192.0.2.0/24")`)
	detectOnly := rule.Rule{RuleID: "watch", EventType: jobevent.NetworkConnect, Condition: `process.exec_path == "/usr/bin/curl"`, Action: rule.RuleActionDetect}
	disable := true

	tests := []struct {
		name        string
		host        *jobscope.JobScopeState
		project     *jobscope.JobScopeState
		wantBlocked []string
		wantAllowed []string
		wantEmpty   bool
	}{
		{
			name:      "no scopes",
			wantEmpty: true,
		},
		{
			name:      "scope without block rules installs nothing",
			host:      resolvedScope(jobscope.NewHost(), false, nil, detectOnly),
			wantEmpty: true,
		},
		{
			name:        "single scope blocks its rules",
			host:        resolvedScope(jobscope.NewHost(), false, nil, metadata, detectOnly),
			wantBlocked: []string{"169.254.169.254"},
			wantAllowed: []string{"192.0.2.1"},
		},
		{
			name:        "host and project rules are unioned",
			host:        resolvedScope(jobscope.NewHost(), false, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, testNet),
			wantBlocked: []string{"169.254.169.254", "192.0.2.1"},
			wantAllowed: []string{"198.51.100.1"},
		},
		{
			name:        "identical rule in both scopes is lowered once",
			host:        resolvedScope(jobscope.NewHost(), false, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, metadata),
			wantBlocked: []string{"169.254.169.254"},
			wantAllowed: []string{"192.0.2.1"},
		},
		{
			name:        "monitor_mode on one scope leaves the other enforcing",
			host:        resolvedScope(jobscope.NewHost(), true, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, testNet),
			wantBlocked: []string{"192.0.2.1"},
			wantAllowed: []string{"169.254.169.254"},
		},
		{
			name:      "monitor_mode resolves every block rule away",
			host:      resolvedScope(jobscope.NewHost(), true, nil, metadata, testNet),
			wantEmpty: true,
		},
		{
			name: "disabled block rule is not enforced",
			host: resolvedScope(jobscope.NewHost(), false, []rule.RuleModifier{{
				ModifierID: "off",
				Targets:    []rule.RuleModifierTarget{{RulesetID: "egress", RuleID: "metadata"}},
				Disable:    &disable,
			}}, metadata),
			wantEmpty: true,
		},
		{
			name: "modifier exception carves out of the block",
			host: resolvedScope(jobscope.NewHost(), false, []rule.RuleModifier{{
				ModifierID:    "allow_one",
				Targets:       []rule.RuleModifierTarget{{RulesetID: "egress", RuleID: "test_net"}},
				AddExceptions: `remote_ip == "192.0.2.53"`,
			}}, testNet),
			wantBlocked: []string{"192.0.2.1"},
			wantAllowed: []string{"192.0.2.53"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program, err := NetBlockProgram(scopeResolvedRules(tc.host), scopeResolvedRules(tc.project))
			if err != nil {
				t.Fatalf("NetBlockProgram: %v", err)
			}
			if (len(program) == 0) != tc.wantEmpty {
				t.Fatalf("program has %d instructions, wantEmpty=%v", len(program), tc.wantEmpty)
			}
			for _, ip := range tc.wantBlocked {
				if !program.Eval(netBlockDest(ip, 443)) {
					t.Errorf("%s is allowed, want blocked", ip)
				}
			}
			for _, ip := range tc.wantAllowed {
				if program.Eval(netBlockDest(ip, 443)) {
					t.Errorf("%s is blocked, want allowed", ip)
				}
			}
		})
	}
}

func TestNetBlockProgramErrors(t *testing.T) {
	t.Parallel()

	var manyRules []rule.Rule
	for i := range netblock.MaxInsns {
		manyRules = append(manyRules, blockRule(fmt.Sprintf("r%d", i), fmt.Sprintf(`remote_port == %d`, i+1)))
	}

	t.Run("process condition names the field", func(t *testing.T) {
		t.Parallel()
		scope := resolvedScope(jobscope.NewHost(), false, nil, blockRule("curl", `process.exec_path == "/usr/bin/curl"`))
		_, err := NetBlockProgram(scopeResolvedRules(scope), nil)
		var conditionErr *celengine.BlockConditionError
		if !errors.As(err, &conditionErr) || conditionErr.Field != "process.exec_path" {
			t.Fatalf("error = %v, want BlockConditionError for process.exec_path", err)
		}
	})

	t.Run("modifier exception outside the destination fails instead of being dropped", func(t *testing.T) {
		t.Parallel()
		scope := resolvedScope(jobscope.NewHost(), false, []rule.RuleModifier{{
			ModifierID:    "apt",
			Targets:       []rule.RuleModifierTarget{{RulesetID: "egress"}},
			AddExceptions: `process.exec_path == "/usr/bin/apt"`,
		}}, blockRule("metadata", `remote_ip == "169.254.169.254"`))
		_, err := NetBlockProgram(scopeResolvedRules(scope), nil)
		var conditionErr *celengine.BlockConditionError
		if !errors.As(err, &conditionErr) || conditionErr.Field != "process.exec_path" {
			t.Fatalf("error = %v, want BlockConditionError for process.exec_path", err)
		}
	})

	t.Run("more rules than the kernel program holds", func(t *testing.T) {
		t.Parallel()
		scope := resolvedScope(jobscope.NewHost(), false, nil, manyRules...)
		if _, err := NetBlockProgram(scopeResolvedRules(scope), nil); !errors.Is(err, netblock.ErrProgramTooLarge) {
			t.Fatalf("error = %v, want %v", err, netblock.ErrProgramTooLarge)
		}
	})

	t.Run("scopes that each fit can exceed the limit together", func(t *testing.T) {
		t.Parallel()
		half := len(manyRules) / 2
		host := resolvedScope(jobscope.NewHost(), false, nil, manyRules[:half]...)
		project := resolvedScope(jobscope.NewProject(), false, nil, manyRules[half:]...)
		if _, err := NetBlockProgram(scopeResolvedRules(host), nil); err != nil {
			t.Fatalf("host alone: %v", err)
		}
		if _, err := NetBlockProgram(scopeResolvedRules(host), scopeResolvedRules(project)); !errors.Is(err, netblock.ErrProgramTooLarge) {
			t.Fatalf("error = %v, want %v", err, netblock.ErrProgramTooLarge)
		}
	})
}

// netBlockPropertyAddrs are the addresses the generator builds literals and
// destinations from. Keeping the universe small makes matches frequent.
var netBlockPropertyAddrs = []string{
	"10.20.0.1", "10.20.1.200", "10.255.255.255", "169.254.169.254", "192.0.2.1", "192.0.2.255",
	"198.51.100.7", "127.0.0.1", "0.0.0.0", "255.255.255.255",
	"::1", "::", "2001:db8::1", "2001:db8:ffff::1", "fe80::1", "64:ff9b::c000:201", "::fffe:192.0.2.1",
	"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
}

var netBlockPropertyPorts = []uint16{1, 53, 80, 443, 8080, 65535}

type netBlockRuleGenerator struct {
	rng *rand.Rand
}

func (g netBlockRuleGenerator) pick(options ...string) string {
	return options[g.rng.IntN(len(options))]
}

func (g netBlockRuleGenerator) addr() netip.Addr {
	return netip.MustParseAddr(netBlockPropertyAddrs[g.rng.IntN(len(netBlockPropertyAddrs))])
}

func (g netBlockRuleGenerator) leaf() string {
	switch g.rng.IntN(6) {
	case 0:
		ip := g.addr().String()
		if g.rng.IntN(2) == 0 {
			ip = strings.ToUpper(ip)
		}
		if g.rng.IntN(4) == 0 {
			return fmt.Sprintf(`%q == remote_ip`, ip)
		}
		return fmt.Sprintf(`remote_ip == %q`, ip)
	case 1, 2:
		// The base is deliberately left unmasked, and prefix lengths cover
		// both ends so catch-all and host prefixes are exercised.
		addr := g.addr()
		return fmt.Sprintf(`inIpRange(remote_ip, "%s/%d")`, addr, g.rng.IntN(addr.BitLen()+1))
	case 3:
		return fmt.Sprintf(`remote_port == %d`, netBlockPropertyPorts[g.rng.IntN(len(netBlockPropertyPorts))])
	case 4:
		return fmt.Sprintf(`protocol == %q`, g.pick("tcp", "udp", "TCP"))
	default:
		return fmt.Sprintf(`family == %q`, g.pick("ipv4", "ipv6"))
	}
}

func (g netBlockRuleGenerator) expr(depth int) string {
	if depth == 0 || g.rng.IntN(4) == 0 {
		return g.leaf()
	}
	switch g.rng.IntN(5) {
	case 0:
		return "!(" + g.expr(depth-1) + ")"
	case 1, 2:
		return "(" + g.expr(depth-1) + " && " + g.expr(depth-1) + ")"
	default:
		return "(" + g.expr(depth-1) + " || " + g.expr(depth-1) + ")"
	}
}

func (g netBlockRuleGenerator) rules() []rule.Rule {
	rules := make([]rule.Rule, 1+g.rng.IntN(2))
	for i := range rules {
		rules[i] = blockRule(fmt.Sprintf("r%d", i), g.expr(2))
		if g.rng.IntN(2) == 0 {
			rules[i].Exceptions = g.expr(1)
		}
	}
	return rules
}

func (g netBlockRuleGenerator) dest() netblock.Tuple {
	addr := g.addr().As16()
	// Flip a few bits so destinations land just inside and outside prefixes.
	for range g.rng.IntN(3) {
		addr[g.rng.IntN(len(addr))] ^= 1 << g.rng.IntN(8)
	}
	proto := netblock.ProtoTCP
	if g.rng.IntN(2) == 0 {
		proto = netblock.ProtoUDP
	}
	return netblock.Tuple{Addr: addr, Port: netBlockPropertyPorts[g.rng.IntN(len(netBlockPropertyPorts))], Proto: proto}
}

// netBlockEvent renders dst the way KernelTracker reports a connect sample:
// IPv4-mapped destinations become dotted IPv4 with family "ipv4".
func netBlockEvent(dst netblock.Tuple) jobevent.EventRecord {
	remoteIP, family := net.IP(dst.Addr[:]).String(), "ipv6"
	if v4 := net.IP(dst.Addr[:]).To4(); v4 != nil {
		remoteIP, family = v4.String(), "ipv4"
	}
	protocol := "tcp"
	if dst.Proto == netblock.ProtoUDP {
		protocol = "udp"
	}
	return jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
		Payload: map[string]any{
			"remote_ip":   remoteIP,
			"remote_port": int(dst.Port),
			"protocol":    protocol,
			"family":      family,
		},
		Tags: map[string]string{},
	}
}

// TestNetBlockProgramAgreesWithCEL is the equivalence check between the two
// definitions of a block rule: for random block-compatible rule sets and
// random destinations, the lowered program must decide exactly as rule
// evaluation does.
func TestNetBlockProgramAgreesWithCEL(t *testing.T) {
	t.Parallel()

	const (
		ruleSets        = 400
		destsPerRuleSet = 64
	)
	compared, blocked := 0, 0
	for seed := range uint64(ruleSets) {
		gen := netBlockRuleGenerator{rng: rand.New(rand.NewPCG(seed, 0x6e6574626c6f636b))}
		rules := gen.rules()
		scope := resolvedScope(jobscope.NewHost(), false, nil, rules...)

		program, err := NetBlockProgram(scopeResolvedRules(scope), nil)
		if errors.Is(err, netblock.ErrProgramTooLarge) {
			continue
		}
		if err != nil {
			t.Fatalf("seed %d: generated rules must be block-compatible: %v\nrules: %+v", seed, err, rules)
		}
		eval := NewEvaluationState(scopeResolvedRules(scope), nil)
		if len(scope.ResolvedRules.Warnings) != 0 {
			t.Fatalf("seed %d: CEL compile warnings: %+v\nrules: %+v", seed, scope.ResolvedRules.Warnings, rules)
		}

		hits := func() (total int64) {
			for _, r := range rules {
				total += scope.CorrelationHitCountFor(rule.RuleIdentity{RulesetID: "egress", RuleID: r.RuleID})
			}
			return total
		}
		for range destsPerRuleSet {
			dst := gen.dest()
			event := netBlockEvent(dst)
			before := hits()
			EvaluateEvent(testCtx, eval, event, testEvalIdentity, jobcontext.JobMetadata{}, "machine", scope, nil, testLogger, testActivation())
			celBlocks := hits() > before

			if got := program.Eval(dst); got != celBlocks {
				t.Fatalf("seed %d: program blocks=%v, CEL blocks=%v for %v\nrules: %+v", seed, got, celBlocks, event.Payload, rules)
			}
			compared++
			if celBlocks {
				blocked++
			}
		}
	}

	// Guard against a generator that stops exercising one of the outcomes.
	if compared < ruleSets*destsPerRuleSet/2 || blocked < compared/10 || blocked > compared*9/10 {
		t.Fatalf("weak coverage: compared %d decisions, %d blocked", compared, blocked)
	}
}

// blockedConnectEvent is a connect the kernel refused, as KernelTracker
// reports it.
func blockedConnectEvent(dst netblock.Tuple) jobevent.EventRecord {
	event := netBlockEvent(dst)
	event.Tags[jobevent.TagBlockSource] = jobevent.BlockSourceKernel
	return event
}

func hitActions(scope *jobscope.JobScopeState) map[string]string {
	actions := map[string]string{}
	for _, hit := range scope.ObservationSnapshot().Hits {
		actions[hit.RuleID] = hit.Action
	}
	return actions
}

func TestEvaluateEvent_BlockedConnect(t *testing.T) {
	t.Parallel()

	metadata := blockRule("metadata", `remote_ip == "169.254.169.254"`)
	testNet := blockRule("test_net", `inIpRange(remote_ip, "192.0.2.0/24")`)
	killCurl := rule.Rule{RuleID: "kill", EventType: jobevent.NetworkConnect, Condition: `remote_ip == "203.0.113.9"`, Action: rule.RuleActionTerminate}
	metadataDst := netBlockDest("169.254.169.254", 80)

	tests := []struct {
		name        string
		host        *jobscope.JobScopeState
		project     *jobscope.JobScopeState
		event       jobevent.EventRecord
		wantHost    map[string]string
		wantProject map[string]string
		wantLog     string
		wantNoLog   string
	}{
		{
			name:      "blocked connect records a block hit",
			host:      resolvedScope(jobscope.NewHost(), false, nil, metadata),
			event:     blockedConnectEvent(metadataDst),
			wantHost:  map[string]string{"metadata": "block"},
			wantNoLog: "network_block",
		},
		{
			name:        "hit is routed only to the scope that owns the rule",
			host:        resolvedScope(jobscope.NewHost(), false, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, testNet),
			event:       blockedConnectEvent(metadataDst),
			wantHost:    map[string]string{"metadata": "block"},
			wantProject: map[string]string{},
			wantNoLog:   "network_block",
		},
		{
			name:        "rule shared by both scopes is recorded in each",
			host:        resolvedScope(jobscope.NewHost(), false, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, metadata),
			event:       blockedConnectEvent(metadataDst),
			wantHost:    map[string]string{"metadata": "block"},
			wantProject: map[string]string{"metadata": "block"},
		},
		{
			name:        "monitor_mode scope records detect while the other records block",
			host:        resolvedScope(jobscope.NewHost(), true, nil, metadata),
			project:     resolvedScope(jobscope.NewProject(), false, nil, metadata),
			event:       blockedConnectEvent(metadataDst),
			wantHost:    map[string]string{"metadata": "detect"},
			wantProject: map[string]string{"metadata": "block"},
		},
		{
			name:      "monitor_mode alone: allowed connect records a detect hit",
			host:      resolvedScope(jobscope.NewHost(), true, nil, metadata),
			event:     netBlockEvent(metadataDst),
			wantHost:  map[string]string{"metadata": "detect"},
			wantNoLog: "network_block",
		},
		{
			name:     "block rule matching a connect the kernel let through is flagged",
			host:     resolvedScope(jobscope.NewHost(), false, nil, metadata),
			event:    netBlockEvent(metadataDst),
			wantHost: map[string]string{"metadata": "block"},
			wantLog:  "network_block_not_enforced",
		},
		{
			name:     "blocked connect that no block rule explains is a mismatch",
			host:     resolvedScope(jobscope.NewHost(), false, nil, testNet),
			event:    blockedConnectEvent(metadataDst),
			wantHost: map[string]string{},
			wantLog:  "network_block_mismatch",
		},
		{
			name:     "non-block rules still evaluate on a blocked connect",
			host:     resolvedScope(jobscope.NewHost(), false, nil, blockRule("deny", `remote_ip == "203.0.113.9"`), killCurl),
			event:    blockedConnectEvent(netBlockDest("203.0.113.9", 443)),
			wantHost: map[string]string{"deny": "block", "kill": "terminate"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			eval := NewEvaluationState(scopeResolvedRules(tc.host), scopeResolvedRules(tc.project))

			// PID 0 keeps the terminate case from signalling anything.
			EvaluateEvent(testCtx, eval, tc.event, testEvalIdentity, jobcontext.JobMetadata{}, "machine", tc.host, tc.project, logger, testActivation())

			if got := hitActions(tc.host); !maps.Equal(got, tc.wantHost) {
				t.Errorf("host hits = %v, want %v", got, tc.wantHost)
			}
			if tc.project != nil {
				if got := hitActions(tc.project); !maps.Equal(got, tc.wantProject) {
					t.Errorf("project hits = %v, want %v", got, tc.wantProject)
				}
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Errorf("log %q not emitted; logs: %s", tc.wantLog, logs.String())
			}
			if tc.wantNoLog != "" && strings.Contains(logs.String(), tc.wantNoLog) {
				t.Errorf("unexpected %q log: %s", tc.wantNoLog, logs.String())
			}
		})
	}
}

func TestEvaluateEvent_BlockHitsWriteCappedDetectionLogs(t *testing.T) {
	t.Parallel()

	recorder := &recordingEvaluationBatches{}
	deny := blockRule("deny", `remote_ip == "192.0.2.1"`)
	deny.MaxAlerts = 2
	host := resolvedScope(jobscope.NewHost(), false, nil, deny)
	host.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testEvalIdentity, host.Type, recorder.sendBatch)
	eval := NewEvaluationState(scopeResolvedRules(host), nil)

	// A retry loop against a blocked destination.
	for range 5 {
		EvaluateEvent(testCtx, eval, blockedConnectEvent(netBlockDest("192.0.2.1", 443)), testEvalIdentity, jobcontext.JobMetadata{}, "machine", host, nil, testLogger, testActivation())
	}
	if err := host.FinalizeStreamingLogs(testCtx); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	detections := recorder.detectionEntries(t)
	if len(detections) != 2 {
		t.Fatalf("detection entries: got %d, want max_alerts=2", len(detections))
	}
	if got := detections[0].GetEvent().GetTags(); !slices.Contains(got, "block_source:kernel") {
		t.Fatalf("detection event tags = %v, want the blocked marker", got)
	}
	if got := host.CorrelationHitCountFor(rule.RuleIdentity{RulesetID: "egress", RuleID: "deny"}); got != 5 {
		t.Fatalf("hit count = %d, want every blocked attempt counted", got)
	}
}
