package vmess

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type testRouter struct {
	adapter.Router
	routed chan adapter.InboundContext
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata
}

func newTestInbound(t *testing.T, count int, options option.VMessInboundOptions) (*Inbound, *testRouter) {
	t.Helper()
	for i := 0; i < count; i++ {
		id := uuid.Must(uuid.NewV4()).String()
		options.Users = append(options.Users, option.VMessUser{Name: id, UUID: id})
	}
	router := &testRouter{routed: make(chan adapter.InboundContext, 4)}
	inbound, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "test", options)
	if err != nil {
		t.Fatal(err)
	}
	return inbound.(*Inbound), router
}

func authenticated(user option.VMessUser) context.Context {
	return auth.ContextWithUser(context.Background(), user)
}

// A connection authenticated before other users are deleted keeps its own
// user; with index keys it was misattributed or indexed out of range.
func TestAuthenticatedUserSurvivesOtherDeletion(t *testing.T) {
	inbound, router := newTestInbound(t, 3, option.VMessInboundOptions{})
	c := inbound.users[2]
	if err := inbound.DelUsers([]string{inbound.users[0].Name}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	inbound.newConnectionEx(authenticated(c), server, adapter.InboundContext{}, nil)
	if metadata := <-router.routed; metadata.User != c.Name {
		t.Fatalf("routed as %q, want %q", metadata.User, c.Name)
	}
}

// A connection authenticated just before its user is deleted, but tracked
// after DelUsers scanned the connections, must still be closed.
func TestDeletedUserConnectionRejected(t *testing.T) {
	inbound, router := newTestInbound(t, 2, option.VMessInboundOptions{})
	a := inbound.users[0]
	if err := inbound.DelUsers([]string{a.Name}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	closed := make(chan error, 1)
	inbound.newConnectionEx(authenticated(a), server, adapter.InboundContext{}, func(err error) {
		closed <- err
	})
	if len(router.routed) != 0 {
		t.Fatal("deleted user was routed")
	}
	if len(closed) != 1 {
		t.Fatal("connection not closed")
	}
}

// Deleting a user closes its open connections; before, they stayed open.
func TestDeleteUserClosesConnections(t *testing.T) {
	inbound, router := newTestInbound(t, 2, option.VMessInboundOptions{})
	a, b := inbound.users[0], inbound.users[1]
	clientA, serverA := net.Pipe()
	defer clientA.Close()
	clientB, serverB := net.Pipe()
	defer clientB.Close()
	inbound.newConnectionEx(authenticated(a), serverA, adapter.InboundContext{}, nil)
	inbound.newConnectionEx(authenticated(b), serverB, adapter.InboundContext{}, nil)
	<-router.routed
	<-router.routed
	if err := inbound.DelUsers([]string{a.Name}); err != nil {
		t.Fatal(err)
	}
	clientA.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientA.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("deleted user connection: %v, want EOF", err)
	}
	clientB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := clientB.Read(make([]byte, 1)); err == io.EOF {
		t.Fatal("remaining user connection closed")
	}
}

// Requests that fail authentication are routed to the fallback with their
// bytes, like trojan.
func TestFallbackRouted(t *testing.T) {
	inbound, router := newTestInbound(t, 1, option.VMessInboundOptions{
		Fallback: &option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
	})
	client, server := net.Pipe()
	defer client.Close()
	go client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	go inbound.NewConnection(context.Background(), server, adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:1234")}, nil)
	select {
	case metadata := <-router.routed:
		if !metadata.Fallback || metadata.Destination != M.ParseSocksaddr("127.0.0.1:8080") {
			t.Fatalf("routed to %v, fallback %v", metadata.Destination, metadata.Fallback)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe not routed to fallback")
	}
}

func TestFallbackForALPNNeedsTLS(t *testing.T) {
	_, err := NewInbound(context.Background(), &testRouter{}, log.NewNOPFactory().Logger(), "test", option.VMessInboundOptions{
		FallbackForALPN: map[string]*option.ServerOptions{"h2": {Server: "127.0.0.1", ServerPort: 8081}},
	})
	if err == nil {
		t.Fatal("ALPN fallback accepted without TLS")
	}
}
