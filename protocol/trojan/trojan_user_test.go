package trojan

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

type testRouter struct {
	adapter.Router
	routed chan string
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata.User
}

func newTestInbound(t *testing.T, names ...string) (*Inbound, *testRouter) {
	t.Helper()
	var users []option.TrojanUser
	for _, name := range names {
		users = append(users, option.TrojanUser{Name: name, Password: "password-" + name})
	}
	router := &testRouter{routed: make(chan string, 1)}
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
