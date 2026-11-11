package v2raygrpc

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type stalledReadHandler struct {
	connections chan net.Conn
	finished    chan struct{}
}

func (h *stalledReadHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer close(h.finished)
	var first [1]byte
	if _, err := conn.Read(first[:]); err != nil {
		onClose(err)
		return
	}
	h.connections <- conn
	_, err := io.Copy(io.Discard, conn)
	onClose(err)
}

func TestServerConnectionCloseInterruptsRecv(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler := &stalledReadHandler{connections: make(chan net.Conn, 1), finished: make(chan struct{})}
	transport := &Server{ctx: context.Background(), handler: handler}
	server := grpc.NewServer()
	RegisterGunServiceServer(server, transport)
	defer server.Stop()
	go server.Serve(listener)
	client, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := NewGunServiceClient(client).Tun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&Hunk{Data: []byte("short")}); err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-handler.connections:
		conn.Close()
	case <-ctx.Done():
		t.Fatal("server did not receive request")
	}
	select {
	case <-handler.finished:
	case <-time.After(time.Second):
		t.Fatal("closing server stream did not interrupt Recv")
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("closed stream returned data")
	}
}
