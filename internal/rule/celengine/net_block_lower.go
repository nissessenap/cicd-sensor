package celengine

import (
	"fmt"
	"net/netip"
	"strings"

	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// BlockConditionError reports a condition or exception that a block rule
// cannot use because the connect hooks cannot evaluate it.
type BlockConditionError struct {
	// Field is the offending field, function, or literal as written.
	Field  string
	Reason string
}

func (e *BlockConditionError) Error() string {
	return fmt.Sprintf("%s: %s; block rules may only combine remote_ip, remote_port, protocol and family with ==, inIpRange, &&, || and !", e.Field, e.Reason)
}

// ipv4MappedPrefix is how the kernel form tells IPv4 destinations from IPv6.
var ipv4MappedPrefix = netip.MustParsePrefix("::ffff:0.0.0.0/96")

// LowerNetBlockRule lowers a resolved block rule to its kernel-evaluable
// form: condition && !exceptions && !add_exceptions.
//
// CEL is the semantic definition; the Program is an equivalent projection.
// Every accepted construct must lower to instructions that agree with the
// CEL result for every destination the connect hooks can report, so anything
// whose CEL meaning is not reproduced exactly is rejected instead of
// approximated.
func (e *Env) LowerNetBlockRule(resolved rule.ResolvedRule) (netblock.Program, error) {
	program, err := e.lowerNetBlockSource(nil, resolved.Rule.Condition)
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}
	if strings.TrimSpace(resolved.Rule.Exceptions) != "" {
		program, err = e.lowerNetBlockException(program, resolved.Rule.Exceptions)
		if err != nil {
			return nil, fmt.Errorf("exceptions: %w", err)
		}
	}
	for _, clause := range resolved.ExceptionClauses {
		program, err = e.lowerNetBlockException(program, clause.Source)
		if err != nil {
			return nil, fmt.Errorf("add_exceptions from modifier %q: %w", clause.ModifierIdentity, err)
		}
	}
	return program, nil
}

func (e *Env) lowerNetBlockException(program netblock.Program, source string) (netblock.Program, error) {
	program, err := e.lowerNetBlockSource(program, source)
	if err != nil {
		return nil, err
	}
	return append(program, netblock.Not(), netblock.And()), nil
}

func (e *Env) lowerNetBlockSource(program netblock.Program, source string) (netblock.Program, error) {
	env, err := e.EnvForType(jobevent.NetworkConnect)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return lowerNetBlockExpr(program, ast.NativeRep().Expr())
}

func lowerNetBlockExpr(program netblock.Program, expr celast.Expr) (netblock.Program, error) {
	if expr.Kind() != celast.CallKind {
		return nil, unsupportedBlockExpr(expr)
	}
	call := expr.AsCall()
	args := call.Args()
	switch call.FunctionName() {
	case operators.LogicalAnd, operators.LogicalOr:
		op := netblock.And()
		if call.FunctionName() == operators.LogicalOr {
			op = netblock.Or()
		}
		for i, arg := range args {
			var err error
			program, err = lowerNetBlockExpr(program, arg)
			if err != nil {
				return nil, err
			}
			if i > 0 {
				program = append(program, op)
			}
		}
		return program, nil
	case operators.LogicalNot:
		program, err := lowerNetBlockExpr(program, args[0])
		if err != nil {
			return nil, err
		}
		return append(program, netblock.Not()), nil
	case operators.Equals:
		return lowerNetBlockEquals(program, expr, args)
	case "inIpRange":
		return lowerNetBlockInIPRange(program, expr, args)
	default:
		return nil, unsupportedBlockExpr(expr)
	}
}

func lowerNetBlockEquals(program netblock.Program, expr celast.Expr, args []celast.Expr) (netblock.Program, error) {
	field, literal := args[0], args[1]
	if field.Kind() == celast.LiteralKind {
		field, literal = literal, field
	}
	if field.Kind() != celast.IdentKind {
		return nil, unsupportedBlockExpr(expr)
	}
	name := field.AsIdent()
	if _, allowed := netBlockFields[name]; !allowed {
		return nil, unsupportedBlockExpr(expr)
	}
	if literal.Kind() != celast.LiteralKind {
		if other := foreignBlockField(literal); other != "" {
			return nil, &BlockConditionError{Field: other, Reason: "is not available to block rules"}
		}
		return nil, &BlockConditionError{Field: name, Reason: "must be compared with a literal"}
	}
	value := literal.AsLiteral().Value()

	switch name {
	case "remote_ip":
		text, ok := value.(string)
		if !ok {
			return nil, &BlockConditionError{Field: name, Reason: "must be compared with a string literal"}
		}
		// CEL compares the rendered address as a string, so only the
		// canonical spelling of an address can ever match.
		addr, err := netip.ParseAddr(rule.NormalizeString(text))
		if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != rule.NormalizeString(text) {
			return nil, &BlockConditionError{Field: name, Reason: fmt.Sprintf("%q is not a canonical IP address", text)}
		}
		return append(program, matchPrefix(netip.PrefixFrom(addr, addr.BitLen()))), nil
	case "remote_port":
		port, ok := value.(int64)
		if !ok || port < 1 || port > 65535 {
			return nil, &BlockConditionError{Field: name, Reason: "must be compared with an integer literal in 1..65535"}
		}
		return append(program, netblock.Match(netblock.Tuple{Port: uint16(port)}, netblock.Tuple{Port: 0xffff})), nil
	case "protocol":
		text, _ := value.(string)
		var proto uint8
		switch rule.NormalizeString(text) {
		case "tcp":
			proto = netblock.ProtoTCP
		case "udp":
			proto = netblock.ProtoUDP
		default:
			return nil, &BlockConditionError{Field: name, Reason: `must be compared with "tcp" or "udp"`}
		}
		return append(program, netblock.Match(netblock.Tuple{Proto: proto}, netblock.Tuple{Proto: 0xff})), nil
	case "family":
		text, _ := value.(string)
		switch rule.NormalizeString(text) {
		case "ipv4":
			return append(program, matchPrefix(ipv4MappedPrefix)), nil
		case "ipv6":
			return append(program, matchPrefix(ipv4MappedPrefix), netblock.Not()), nil
		default:
			return nil, &BlockConditionError{Field: name, Reason: `must be compared with "ipv4" or "ipv6"`}
		}
	}
	return nil, unsupportedBlockExpr(expr)
}

func lowerNetBlockInIPRange(program netblock.Program, expr celast.Expr, args []celast.Expr) (netblock.Program, error) {
	if len(args) != 2 || args[0].Kind() != celast.IdentKind || args[0].AsIdent() != "remote_ip" {
		return nil, &BlockConditionError{Field: "inIpRange", Reason: "first argument must be remote_ip"}
	}
	if args[1].Kind() != celast.LiteralKind {
		return nil, unsupportedBlockExpr(expr)
	}
	text, _ := args[1].AsLiteral().Value().(string)
	prefix, err := netip.ParsePrefix(rule.NormalizeString(text))
	if err != nil || prefix.Addr().Is4In6() {
		// IPv4-mapped CIDRs follow net.IPNet quirks that are not worth
		// mirroring; the IPv4 spelling expresses the same range.
		return nil, &BlockConditionError{Field: "inIpRange", Reason: fmt.Sprintf("%q must be a plain IPv4 or IPv6 CIDR", text)}
	}
	program = append(program, matchPrefix(prefix))
	if prefix.Addr().Is6() && prefix.Contains(ipv4MappedPrefix.Addr()) {
		// An IPv6 CIDR never contains an IPv4 destination in CEL, but the
		// kernel form stores IPv4 as IPv4-mapped, so exclude that range.
		program = append(program,
			matchPrefix(ipv4MappedPrefix),
			netblock.Not(),
			netblock.And(),
		)
	}
	return program, nil
}

// matchPrefix builds the Match for an address prefix. IPv4 prefixes are
// widened into the IPv4-mapped range so they never match IPv6 destinations.
func matchPrefix(prefix netip.Prefix) netblock.Insn {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += ipv4MappedPrefix.Bits()
	}
	var mask netblock.Tuple
	for i := range mask.Addr {
		switch {
		case bits >= 8:
			mask.Addr[i] = 0xff
			bits -= 8
		case bits > 0:
			mask.Addr[i] = ^byte(0xff >> bits)
			bits = 0
		}
	}
	return netblock.Match(netblock.Tuple{Addr: prefix.Addr().As16()}, mask)
}

var netBlockFields = map[string]struct{}{
	"remote_ip":   {},
	"remote_port": {},
	"protocol":    {},
	"family":      {},
}

// foreignBlockField returns the first field in expr that is not part of the
// connect destination, or "" when there is none.
func foreignBlockField(expr celast.Expr) string {
	var field string
	celast.PreOrderVisit(expr, celast.NewExprVisitor(func(e celast.Expr) {
		if field != "" {
			return
		}
		switch e.Kind() {
		case celast.SelectKind:
			if name, ok := selectPath(e); ok {
				field = name
			}
		case celast.IdentKind:
			// "@"-prefixed identifiers are comprehension internals.
			if _, allowed := netBlockFields[e.AsIdent()]; !allowed && !strings.HasPrefix(e.AsIdent(), "@") {
				field = e.AsIdent()
			}
		}
	}))
	return field
}

// unsupportedBlockExpr names what makes expr unusable in a block rule: the
// first field outside the destination, else the function or literal itself.
func unsupportedBlockExpr(expr celast.Expr) error {
	if field := foreignBlockField(expr); field != "" {
		return &BlockConditionError{Field: field, Reason: "is not available to block rules"}
	}
	switch expr.Kind() {
	case celast.CallKind:
		name := expr.AsCall().FunctionName()
		if symbol, ok := operators.FindReverse(name); ok && symbol != "" {
			name = symbol
		}
		return &BlockConditionError{Field: name, Reason: "is not supported in block rules"}
	case celast.LiteralKind:
		return &BlockConditionError{Field: fmt.Sprint(expr.AsLiteral().Value()), Reason: "constant conditions are not supported in block rules"}
	case celast.IdentKind:
		return &BlockConditionError{Field: expr.AsIdent(), Reason: "must be compared with a literal"}
	default:
		return &BlockConditionError{Field: "expression", Reason: "is not supported in block rules"}
	}
}

// selectPath renders `a.b.c` for a select chain rooted at an identifier.
func selectPath(expr celast.Expr) (string, bool) {
	switch expr.Kind() {
	case celast.IdentKind:
		return expr.AsIdent(), true
	case celast.SelectKind:
		sel := expr.AsSelect()
		operand, ok := selectPath(sel.Operand())
		if !ok {
			return "", false
		}
		return operand + "." + sel.FieldName(), true
	default:
		return "", false
	}
}
