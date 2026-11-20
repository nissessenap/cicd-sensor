//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"golang.org/x/sys/unix"
)

// Block rules in these tests only ever name loopback listeners owned by the
// test or documentation ranges (TEST-NET, 2001:db8::/32), because the tracked
// cgroup is the one the test runs in and may hold unrelated processes.

func newNetBlockKernelIO(t *testing.T) (*kernelio.LinuxKernelIO, string) {
	t.Helper()
	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{CgroupV2RootPath: cgroupRoot})
	if err != nil {
		t.Fatalf("kernelio.NewLinux: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })
	return kernelIO, cgroupRoot
}

// startNetBlockJob runs a KernelTracker with blocking enabled and binds the
// test process's cgroup to a fresh Job.
func startNetBlockJob(t *testing.T, name string) (*KernelTracker, jobcontext.JobIdentity, <-chan jobevent.EventRecord) {
	t.Helper()
	kernelIO, cgroupRoot := newNetBlockKernelIO(t)

	ctx, cancel := context.WithCancel(context.Background())
	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	engine.jobTracking.netBlock = newNetBlockTokens()
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run error = %v, want nil", err)
		}
	})

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", name)
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	t.Cleanup(func() { _ = engine.RemoveJob(context.Background(), jobID) })
	return engine, jobID, eventCh
}

func lowerBlockRule(t testing.TB, condition string) netblock.Program {
	t.Helper()
	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("celengine.NewEnv: %v", err)
	}
	program, err := env.LowerNetBlockRule(rule.ResolvedRule{Rule: rule.Rule{
		RuleID:    "block",
		EventType: jobevent.NetworkConnect,
		Condition: condition,
		Action:    rule.RuleActionBlock,
	}})
	if err != nil {
		t.Fatalf("LowerNetBlockRule(%s): %v", condition, err)
	}
	return program
}

// connectSocket calls connect(2) on a fresh socket of the given family and
// type and returns its errno. UDP connects send nothing, so they are safe
// against documentation addresses.
func connectSocket(t *testing.T, family, sotype int, dst netip.AddrPort) error {
	t.Helper()
	fd, err := unix.Socket(family, sotype|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)

	if family == unix.AF_INET {
		return unix.Connect(fd, &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()})
	}
	return unix.Connect(fd, &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()})
}

func loopbackListener(t *testing.T) (*net.TCPListener, netip.AddrPort) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, listener.Addr().(*net.TCPAddr).AddrPort()
}

// acceptWithin reports whether a connection reached the listener in time.
func acceptWithin(t *testing.T, listener *net.TCPListener, timeout time.Duration) bool {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	conn, err := listener.Accept()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	_ = conn.Close()
	return true
}

func waitForConnectEvent(t *testing.T, eventCh <-chan jobevent.EventRecord, port uint16, protocol string) jobevent.EventRecord {
	t.Helper()
	return waitForEventRecord(t, eventCh, 5*time.Second, fmt.Sprintf("network_connect %s port %d", protocol, port), func(record jobevent.EventRecord) bool {
		remotePort, _ := record.Payload["remote_port"].(int)
		recordProtocol, _ := record.Payload["protocol"].(string)
		return record.EventType == jobevent.NetworkConnect && remotePort == int(port) && recordProtocol == protocol
	})
}

func TestLinuxNetBlockRefusesMatchingConnects(t *testing.T) {
	engine, jobID, eventCh := startNetBlockJob(t, "net-block")
	ctx := t.Context()

	blockedListener, blocked := loopbackListener(t)
	allowedListener, allowed := loopbackListener(t)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(blocked.Addr().As16()), blocked.Port())

	if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); err != nil {
		t.Fatalf("connect before install = %v, want success", err)
	}
	if !acceptWithin(t, blockedListener, 2*time.Second) {
		t.Fatal("listener saw no connection before install")
	}
	if event := waitForConnectEvent(t, eventCh, blocked.Port(), "tcp"); event.BlockedByKernel() {
		t.Fatal("connect before install was reported as blocked")
	}

	program := lowerBlockRule(t, fmt.Sprintf(`remote_ip == "127.0.0.1" && remote_port == %d`, blocked.Port()))
	if err := engine.SetJobNetBlockProgram(ctx, jobID, program); err != nil {
		t.Fatalf("SetJobNetBlockProgram: %v", err)
	}

	t.Run("TCP connect to the blocked address returns EPERM and never reaches the listener", func(t *testing.T) {
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect = %v, want EPERM", err)
		}
		if acceptWithin(t, blockedListener, 300*time.Millisecond) {
			t.Fatal("listener accepted a connection the kernel should have refused")
		}
		event := waitForConnectEvent(t, eventCh, blocked.Port(), "tcp")
		if !event.BlockedByKernel() {
			t.Fatalf("blocked connect event is not marked blocked: tags=%v", event.Tags)
		}
		if remoteIP, _ := event.Payload["remote_ip"].(string); remoteIP != "127.0.0.1" {
			t.Fatalf("blocked event remote_ip = %q, want 127.0.0.1", remoteIP)
		}
	})

	t.Run("IPv4-mapped destination on an IPv6 socket is the same blocked address", func(t *testing.T) {
		if err := connectSocket(t, unix.AF_INET6, unix.SOCK_STREAM, mapped); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect = %v, want EPERM", err)
		}
		if acceptWithin(t, blockedListener, 300*time.Millisecond) {
			t.Fatal("listener accepted a connection the kernel should have refused")
		}
		event := waitForConnectEvent(t, eventCh, blocked.Port(), "tcp")
		if family, _ := event.Payload["family"].(string); !event.BlockedByKernel() || family != "ipv4" {
			t.Fatalf("event blocked=%v family=%q, want blocked ipv4", event.BlockedByKernel(), family)
		}
	})

	t.Run("connected UDP to the blocked address returns EPERM", func(t *testing.T) {
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_DGRAM, blocked); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect = %v, want EPERM", err)
		}
		if event := waitForConnectEvent(t, eventCh, blocked.Port(), "udp"); !event.BlockedByKernel() {
			t.Fatalf("blocked UDP connect event is not marked blocked: tags=%v", event.Tags)
		}
	})

	// Linux routes the wildcard address to loopback, but the hook and CEL
	// both see the destination as written, so a rule naming 127.0.0.1 does
	// not cover it.
	t.Run("wildcard destination reaches the blocked listener unmatched", func(t *testing.T) {
		wildcard := netip.AddrPortFrom(netip.IPv4Unspecified(), blocked.Port())
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, wildcard); err != nil {
			t.Fatalf("connect = %v, want success", err)
		}
		if !acceptWithin(t, blockedListener, 2*time.Second) {
			t.Fatal("listener saw no connection for the wildcard destination")
		}
		event := waitForConnectEvent(t, eventCh, blocked.Port(), "tcp")
		if remoteIP, _ := event.Payload["remote_ip"].(string); event.BlockedByKernel() || remoteIP != "0.0.0.0" {
			t.Fatalf("event blocked=%v remote_ip=%q, want unblocked 0.0.0.0", event.BlockedByKernel(), remoteIP)
		}
	})

	t.Run("connect to a non-matching address succeeds", func(t *testing.T) {
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, allowed); err != nil {
			t.Fatalf("connect = %v, want success", err)
		}
		if !acceptWithin(t, allowedListener, 2*time.Second) {
			t.Fatal("listener saw no connection for an allowed destination")
		}
		if event := waitForConnectEvent(t, eventCh, allowed.Port(), "tcp"); event.BlockedByKernel() {
			t.Fatal("allowed connect was reported as blocked")
		}
	})

	t.Run("child cgroup created after install is blocked from its first connect", func(t *testing.T) {
		enterChildCgroup(t, engine.cgroupV2RootPath)
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect from child cgroup = %v, want EPERM", err)
		}
		if acceptWithin(t, blockedListener, 300*time.Millisecond) {
			t.Fatal("listener accepted a connection from the child cgroup")
		}
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, allowed); err != nil {
			t.Fatalf("allowed connect from child cgroup = %v, want success", err)
		}
	})

	t.Run("replacing the program switches every cgroup to the new rules", func(t *testing.T) {
		replacement := lowerBlockRule(t, fmt.Sprintf(`remote_ip == "127.0.0.1" && remote_port == %d`, allowed.Port()))
		if err := engine.SetJobNetBlockProgram(ctx, jobID, replacement); err != nil {
			t.Fatalf("SetJobNetBlockProgram: %v", err)
		}
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, allowed); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect to newly blocked address = %v, want EPERM", err)
		}
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); err != nil {
			t.Fatalf("connect to no longer blocked address = %v, want success", err)
		}
	})

	t.Run("removing the job stops enforcement", func(t *testing.T) {
		if err := engine.RemoveJob(ctx, jobID); err != nil {
			t.Fatalf("RemoveJob: %v", err)
		}
		if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, allowed); err != nil {
			t.Fatalf("connect after job removal = %v, want success", err)
		}
	})
}

func TestLinuxNetBlockRefusesNativeIPv6Connect(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	blocked := listener.Addr().(*net.TCPAddr).AddrPort()

	engine, jobID, eventCh := startNetBlockJob(t, "net-block-ipv6")
	program := lowerBlockRule(t, fmt.Sprintf(`remote_ip == "::1" && remote_port == %d`, blocked.Port()))
	if err := engine.SetJobNetBlockProgram(t.Context(), jobID, program); err != nil {
		t.Fatalf("SetJobNetBlockProgram: %v", err)
	}

	if err := connectSocket(t, unix.AF_INET6, unix.SOCK_STREAM, blocked); !errors.Is(err, unix.EPERM) {
		t.Fatalf("connect = %v, want EPERM", err)
	}
	if acceptWithin(t, listener, 300*time.Millisecond) {
		t.Fatal("listener accepted a connection the kernel should have refused")
	}
	event := waitForConnectEvent(t, eventCh, blocked.Port(), "tcp")
	if family, _ := event.Payload["family"].(string); !event.BlockedByKernel() || family != "ipv6" {
		t.Fatalf("event blocked=%v family=%q, want blocked ipv6", event.BlockedByKernel(), family)
	}
}

// TestLinuxNetBlockStaleTrackingEntryIsNotEnforced leaves a tracking entry
// behind for a Job whose program is gone, as happens when the kernel tracked
// a cgroup userspace never learned about. A later Job's program must not
// apply to it.
func TestLinuxNetBlockStaleTrackingEntryIsNotEnforced(t *testing.T) {
	kernelIO, cgroupRoot := newNetBlockKernelIO(t)
	ctx := t.Context()

	listener, blocked := loopbackListener(t)
	program := lowerBlockRule(t, fmt.Sprintf(`remote_ip == "127.0.0.1" && remote_port == %d`, blocked.Port()))

	const removedJobToken, laterJobToken = 1, 2
	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID, removedJobToken); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	})
	if err := kernelIO.InstallNetBlockProgram(ctx, removedJobToken, program); err != nil {
		t.Fatalf("InstallNetBlockProgram: %v", err)
	}
	if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); !errors.Is(err, unix.EPERM) {
		t.Fatalf("connect while the job's program is installed = %v, want EPERM", err)
	}

	if err := kernelIO.DeleteNetBlockProgram(ctx, removedJobToken); err != nil {
		t.Fatalf("DeleteNetBlockProgram: %v", err)
	}
	if err := kernelIO.DeleteNetBlockProgram(ctx, removedJobToken); err != nil {
		t.Fatalf("DeleteNetBlockProgram for a token without a program = %v, want nil", err)
	}
	if err := kernelIO.InstallNetBlockProgram(ctx, laterJobToken, program); err != nil {
		t.Fatalf("InstallNetBlockProgram: %v", err)
	}

	if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); err != nil {
		t.Fatalf("connect from the leftover cgroup = %v, want success", err)
	}
	if !acceptWithin(t, listener, 2*time.Second) {
		t.Fatal("listener saw no connection from the leftover cgroup")
	}
}

// enterChildCgroup creates a cgroup under the test's current one and moves
// the test process into it until the test ends.
func enterChildCgroup(t *testing.T, cgroupRoot string) {
	t.Helper()
	parentPath, err := currentCgroupPath(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}
	childDir := mustCgroupFSPath(t, cgroupRoot, parentPath, fmt.Sprintf("cicd-sensor-net-block-%d", time.Now().UnixNano()))
	if err := os.Mkdir(childDir, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", childDir, err)
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	t.Cleanup(func() {
		_ = os.WriteFile(mustCgroupFSPath(t, cgroupRoot, parentPath, "cgroup.procs"), pid, 0)
		_ = os.Remove(childDir)
	})
	if err := os.WriteFile(filepath.Join(childDir, "cgroup.procs"), pid, 0); err != nil {
		t.Fatalf("move test process into %q: %v", childDir, err)
	}
}

// TestLinuxNetBlockTokenIsInheritedInKernel covers the three ways a cgroup
// becomes tracked without userspace: each must copy the Job's token in the
// same hook that starts tracking, or the new cgroup would run unenforced.
func TestLinuxNetBlockTokenIsInheritedInKernel(t *testing.T) {
	kernelIO, cgroupRoot := newNetBlockKernelIO(t)
	ctx := t.Context()

	const token = 3
	selfPath, err := currentCgroupPath(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("currentCgroupPath: %v", err)
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	mkdirCgroup := func(t *testing.T, parentPath, name string) (string, uint64) {
		t.Helper()
		path := filepath.Join(parentPath, name)
		dir := mustCgroupFSPath(t, cgroupRoot, path)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", dir, err)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
		id, err := cgroupIDForPath(cgroupRoot, path)
		if err != nil {
			t.Fatalf("cgroupIDForPath(%q): %v", path, err)
		}
		t.Cleanup(func() {
			_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{id})
		})
		return path, id
	}
	requireToken := func(t *testing.T, cgroupID uint64, want uint32) {
		t.Helper()
		got, tracked, err := kernelIO.TestOnlyLookupNetBlockToken(ctx, cgroupID)
		if err != nil {
			t.Fatalf("TestOnlyLookupNetBlockToken: %v", err)
		}
		if !tracked || got != want {
			t.Fatalf("cgroup tracked=%v token=%d, want tracked with token %d", tracked, got, want)
		}
	}
	unique := func(prefix string) string { return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()) }

	// The test's own cgroup stays untracked, so only the paths under test
	// can put entries into tracked_cgroups.
	trackedPath, trackedID := mkdirCgroup(t, selfPath, unique("cicd-sensor-net-block-tracked"))
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, trackedID, token); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
	}

	t.Run("cgroup created under a tracked cgroup", func(t *testing.T) {
		_, childID := mkdirCgroup(t, trackedPath, "child")
		requireToken(t, childID, token)
	})

	t.Run("staged cgroup basename promoted by cgroup_mkdir", func(t *testing.T) {
		basename := unique("docker-cicd-net-block") + ".scope"
		if err := kernelIO.PutCgroupBasenameInStagingMap(ctx, basename, token); err != nil {
			t.Fatalf("PutCgroupBasenameInStagingMap: %v", err)
		}
		t.Cleanup(func() {
			_ = kernelIO.DeleteCgroupBasenamesFromStagingMap(context.Background(), []string{basename})
		})
		_, stagedID := mkdirCgroup(t, selfPath, basename)
		requireToken(t, stagedID, token)
	})

	t.Run("untracked cgroup a tracked process moves into", func(t *testing.T) {
		destinationPath, destinationID := mkdirCgroup(t, selfPath, unique("cicd-sensor-net-block-destination"))
		if _, tracked, err := kernelIO.TestOnlyLookupNetBlockToken(ctx, destinationID); err != nil || tracked {
			t.Fatalf("destination tracked=%v err=%v before the move, want untracked", tracked, err)
		}
		t.Cleanup(func() {
			_ = os.WriteFile(mustCgroupFSPath(t, cgroupRoot, selfPath, "cgroup.procs"), pid, 0)
		})
		for _, path := range []string{trackedPath, destinationPath} {
			if err := os.WriteFile(mustCgroupFSPath(t, cgroupRoot, path, "cgroup.procs"), pid, 0); err != nil {
				t.Fatalf("move test process into %q: %v", path, err)
			}
		}
		requireToken(t, destinationID, token)
	})
}

// TestLinuxNetBlockKernelAgreesWithReference checks the in-kernel evaluator
// against netblock.Program.Eval on real connects.
func TestLinuxNetBlockKernelAgreesWithReference(t *testing.T) {
	engine, jobID, _ := startNetBlockJob(t, "net-block-reference")
	ctx := t.Context()

	// Every condition is confined to documentation ranges, negations
	// included, so nothing else in the tracked cgroup can be refused.
	const docRanges = `(inIpRange(remote_ip, "192.0.2.0/24") || inIpRange(remote_ip, "198.51.100.0/24") || inIpRange(remote_ip, "203.0.113.0/24") || inIpRange(remote_ip, "2001:db8::/32"))`
	conditions := []string{
		`remote_ip == "192.0.2.1"`,
		`inIpRange(remote_ip, "192.0.2.0/25")`,
		docRanges + ` && !(inIpRange(remote_ip, "198.51.100.0/24") || inIpRange(remote_ip, "2001:db8:1::/48"))`,
		`inIpRange(remote_ip, "203.0.113.0/24") && remote_port == 443 && protocol == "udp"`,
		docRanges + ` && family == "ipv6" && !(remote_ip == "2001:db8:1::1")`,
		docRanges + ` && (family == "ipv4" && remote_port == 53 || protocol == "tcp")`,
		docRanges + ` && inIpRange(remote_ip, "::/0")`,
	}
	type destination struct {
		family int
		dst    netip.AddrPort
	}
	destinations := []destination{
		{unix.AF_INET, netip.MustParseAddrPort("192.0.2.1:443")},
		{unix.AF_INET, netip.MustParseAddrPort("192.0.2.127:53")},
		{unix.AF_INET, netip.MustParseAddrPort("192.0.2.128:443")},
		{unix.AF_INET, netip.MustParseAddrPort("198.51.100.9:443")},
		{unix.AF_INET, netip.MustParseAddrPort("203.0.113.7:443")},
		{unix.AF_INET, netip.MustParseAddrPort("203.0.113.7:80")},
		{unix.AF_INET6, netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")},
		{unix.AF_INET6, netip.MustParseAddrPort("[::ffff:203.0.113.7]:53")},
		{unix.AF_INET6, netip.MustParseAddrPort("[2001:db8:1::1]:443")},
		{unix.AF_INET6, netip.MustParseAddrPort("[2001:db8:2::1]:53")},
		{unix.AF_INET6, netip.MustParseAddrPort("[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:443")},
	}

	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			program := lowerBlockRule(t, condition)
			if err := engine.SetJobNetBlockProgram(ctx, jobID, program); err != nil {
				t.Fatalf("SetJobNetBlockProgram: %v", err)
			}
			for _, d := range destinations {
				want := program.Eval(netblock.Tuple{Addr: d.dst.Addr().As16(), Port: d.dst.Port(), Proto: netblock.ProtoUDP})
				// A refused connect is EPERM; anything else, including an
				// unreachable documentation address, means the hook allowed it.
				got := errors.Is(connectSocket(t, d.family, unix.SOCK_DGRAM, d.dst), unix.EPERM)
				if got != want {
					t.Errorf("connect %s: kernel blocked=%v, reference blocked=%v", d.dst, got, want)
				}
			}
		})
	}
}

// TestLinuxNetBlockEnforcesWithoutRingbufSpace fills the events ring buffer
// and checks that a blocked connect is still refused when its sample cannot
// be reserved.
func TestLinuxNetBlockEnforcesWithoutRingbufSpace(t *testing.T) {
	kernelIO, cgroupRoot := newNetBlockKernelIO(t)
	ctx := t.Context()

	listener, blocked := loopbackListener(t)
	program := lowerBlockRule(t, fmt.Sprintf(`remote_ip == "127.0.0.1" && remote_port == %d`, blocked.Port()))

	const token = 1
	if err := kernelIO.InstallNetBlockProgram(ctx, token, program); err != nil {
		t.Fatalf("InstallNetBlockProgram: %v", err)
	}
	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID, token); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	})

	// Nothing reads the ring buffer here, so allowed connects fill it.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)
	filler := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
	deadline := time.Now().Add(2 * time.Minute)
	for full := false; !full; {
		if time.Now().After(deadline) {
			t.Fatal("events ring buffer did not fill")
		}
		for range 50_000 {
			if err := unix.Connect(fd, filler); err != nil {
				t.Fatalf("filler connect: %v", err)
			}
		}
		dropped, err := kernelIO.TestOnlyRingbufDropCount()
		if err != nil {
			t.Fatalf("TestOnlyRingbufDropCount: %v", err)
		}
		full = dropped > 0
	}

	droppedBefore, err := kernelIO.TestOnlyRingbufDropCount()
	if err != nil {
		t.Fatalf("TestOnlyRingbufDropCount: %v", err)
	}
	if err := connectSocket(t, unix.AF_INET, unix.SOCK_STREAM, blocked); !errors.Is(err, unix.EPERM) {
		t.Fatalf("connect with a full ring buffer = %v, want EPERM", err)
	}
	if acceptWithin(t, listener, 300*time.Millisecond) {
		t.Fatal("listener accepted a connection the kernel should have refused")
	}
	droppedAfter, err := kernelIO.TestOnlyRingbufDropCount()
	if err != nil {
		t.Fatalf("TestOnlyRingbufDropCount: %v", err)
	}
	if droppedAfter <= droppedBefore {
		t.Fatalf("drop count %d -> %d: the blocked connect's sample was not dropped, so the test did not exercise the full-buffer path", droppedBefore, droppedAfter)
	}
}

// BenchmarkLinuxNetBlockConnect measures connect(2) on a UDP socket, which
// runs the cgroup/connect4 hook and sends no packet.
func BenchmarkLinuxNetBlockConnect(b *testing.B) {
	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		b.Fatalf("getCgroupV2Root: %v", err)
	}
	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		b.Fatalf("lookupProcessCgroupID: %v", err)
	}

	// Programs only name documentation addresses, so they cost evaluation
	// time on every connect in the tracked cgroup but refuse none of them.
	smallProgram := lowerBlockRule(b, `inIpRange(remote_ip, "192.0.2.0/24") && !inIpRange(remote_ip, "192.0.2.0/25")`)
	fullProgram := lowerBlockRule(b, `remote_ip == "192.0.2.1"`)
	for len(fullProgram)+2 <= netblock.MaxInsns {
		fullProgram = append(fullProgram, fullProgram[0], netblock.Or())
	}

	cases := []struct {
		name    string
		tracked bool
		program netblock.Program
	}{
		{name: "untracked cgroup"},
		{name: "tracked, no program", tracked: true},
		{name: fmt.Sprintf("tracked, %d instructions", len(smallProgram)), tracked: true, program: smallProgram},
		{name: fmt.Sprintf("tracked, %d instructions", len(fullProgram)), tracked: true, program: fullProgram},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{CgroupV2RootPath: cgroupRoot})
			if err != nil {
				b.Fatalf("kernelio.NewLinux: %v", err)
			}
			defer kernelIO.Close()
			ctx := b.Context()
			// Drain samples so the allow path keeps paying for reserve+submit.
			if err := kernelIO.StartKernelSampleLoop(ctx, func(context.Context, kernelio.KernelSample) error { return nil }); err != nil {
				b.Fatalf("StartKernelSampleLoop: %v", err)
			}
			if tc.program != nil {
				if err := kernelIO.InstallNetBlockProgram(ctx, 1, tc.program); err != nil {
					b.Fatalf("InstallNetBlockProgram: %v", err)
				}
			}
			if tc.tracked {
				if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID, 1); err != nil {
					b.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
				}
				defer kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
			}

			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				b.Fatalf("socket: %v", err)
			}
			defer unix.Close(fd)
			dst := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
			for b.Loop() {
				if err := unix.Connect(fd, dst); err != nil {
					b.Fatalf("connect: %v", err)
				}
			}
		})
	}
}
