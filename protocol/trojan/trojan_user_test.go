package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	trojanTransport "github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testRouter struct {
	adapter.Router
	routed  chan string
	onClose chan N.CloseHandlerFunc
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata.User
	select {
	case r.onClose <- onClose:
	default:
	}
}

func (r *testRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata.User
}

func newTestInbound(t *testing.T, names ...string) (*Inbound, *testRouter) {
	t.Helper()
	var users []option.TrojanUser
	for _, name := range names {
		users = append(users, option.TrojanUser{Name: name, Password: "password-" + name})
	}
	router := &testRouter{routed: make(chan string, 1), onClose: make(chan N.CloseHandlerFunc, 1)}
	inbound, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "test", option.TrojanInboundOptions{Users: users})
	if err != nil {
		t.Fatal(err)
	}
	return inbound.(*Inbound), router
}

func authenticated(user option.TrojanUser) context.Context {
	return auth.ContextWithUser(context.Background(), user)
}

// A connection authenticated before other users are deleted keeps its own
// user; with index keys it was misattributed or indexed out of range.
func TestAuthenticatedUserSurvivesOtherDeletion(t *testing.T) {
	inbound, router := newTestInbound(t, "a", "b", "c")
	c := inbound.users[2]
	if err := inbound.DelUsers([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	inbound.newConnection(authenticated(c), server, adapter.InboundContext{}, nil)
	if user := <-router.routed; user != "c" {
		t.Fatalf("routed as %q", user)
	}
}

// A connection authenticated just before its user is deleted, but tracked
// after DelUsers scanned the connections, must still be closed.
func TestDeletedUserConnectionClosed(t *testing.T) {
	inbound, router := newTestInbound(t, "a", "b")
	a := inbound.users[0]
	if err := inbound.DelUsers([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	closed := make(chan error, 1)
	inbound.newConnection(authenticated(a), server, adapter.InboundContext{}, func(err error) {
		closed <- err
	})
	if len(router.routed) != 0 {
		t.Fatal("deleted user was routed")
	}
	if len(closed) != 1 {
		t.Fatal("connection not closed")
	}
	inbound.userconns.Range(func(key, value any) bool {
		t.Fatal("deleted user connection still tracked")
		return false
	})
}

// expectClosed fails unless the peer of conn has been closed.
func expectClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection not closed: %v", err)
	}
}

// UDP tunnels of a deleted user must be closed like TCP connections, both
// when already routed and when authenticated just before the deletion.
func TestDeletedUserPacketConnectionClosed(t *testing.T) {
	t.Run("routed before deletion", func(t *testing.T) {
		inbound, router := newTestInbound(t, "a", "b")
		a := inbound.users[0]
		client, server := net.Pipe()
		defer client.Close()
		inbound.newPacketConnection(authenticated(a), &trojanTransport.PacketConn{Conn: server}, adapter.InboundContext{}, nil)
		if user := <-router.routed; user != "a" {
			t.Fatalf("routed as %q", user)
		}
		if err := inbound.DelUsers([]string{"a"}); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, client)
	})
	t.Run("authenticated before deletion", func(t *testing.T) {
		inbound, router := newTestInbound(t, "a", "b")
		a := inbound.users[0]
		if err := inbound.DelUsers([]string{"a"}); err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		defer client.Close()
		inbound.newPacketConnection(authenticated(a), &trojanTransport.PacketConn{Conn: server}, adapter.InboundContext{}, nil)
		if len(router.routed) != 0 {
			t.Fatal("deleted user was routed")
		}
		expectClosed(t, client)
		inbound.userconns.Range(func(key, value any) bool {
			t.Fatal("deleted user packet connection still tracked")
			return false
		})
	})
}

func TestFallbackConnectionLimit(t *testing.T) {
	inbound, router := newTestInbound(t, "a")
	inbound.fallbackAddr = M.ParseSocksaddr("127.0.0.1:80")
	inbound.fallbackConns.Store(maxFallbackConnections)
	client, server := net.Pipe()
	defer client.Close()
	inbound.fallbackConnection(context.Background(), server, adapter.InboundContext{}, nil)
	if len(router.routed) != 0 {
		t.Fatal("fallback over the limit was routed")
	}
	expectClosed(t, client)
	if n := inbound.fallbackConns.Load(); n != maxFallbackConnections {
		t.Fatalf("rejected fallback changed the count to %d", n)
	}

	inbound.fallbackConns.Store(0)
	_, server = net.Pipe()
	inbound.fallbackConnection(context.Background(), server, adapter.InboundContext{}, nil)
	<-router.routed
	if n := inbound.fallbackConns.Load(); n != 1 {
		t.Fatalf("active fallbacks %d, want 1", n)
	}
	onClose := <-router.onClose
	onClose(nil)
	onClose(nil)
	if n := inbound.fallbackConns.Load(); n != 0 {
		t.Fatalf("active fallbacks after close %d, want 0", n)
	}
}

type levelLogger struct {
	log.ContextLogger
	lines []string
}

func (l *levelLogger) Error(args ...any) { l.lines = append(l.lines, "error "+fmt.Sprint(args...)) }
func (l *levelLogger) ErrorContext(ctx context.Context, args ...any) {
	l.Error(args...)
}

func (l *levelLogger) DebugContext(ctx context.Context, args ...any) {
	l.lines = append(l.lines, "debug "+fmt.Sprint(args...))
}

func TestFailureLogAggregates(t *testing.T) {
	logger := &levelLogger{ContextLogger: log.NewNOPFactory().Logger()}
	failures := failureLog{interval: 50 * time.Millisecond}
	for i := range 3 {
		failures.log(context.Background(), logger, fmt.Errorf("failure %d", i))
	}
	time.Sleep(60 * time.Millisecond)
	failures.log(context.Background(), logger, fmt.Errorf("failure 3"))
	want := []string{"error failure 0", "debug failure 1", "debug failure 2", "", "error failure 3"}
	if len(logger.lines) != len(want) {
		t.Fatalf("lines %q", logger.lines)
	}
	for i, line := range logger.lines {
		if i == 3 {
			if line[:len("error suppressed 2 ")] != "error suppressed 2 " || line[len(line)-len("last: failure 2"):] != "last: failure 2" {
				t.Fatalf("summary %q", line)
			}
			continue
		}
		if line != want[i] {
			t.Fatalf("line %d: %q, want %q", i, line, want[i])
		}
	}
}
