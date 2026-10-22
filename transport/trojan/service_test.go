package trojan

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testAccepted struct {
	ctx         context.Context
	conn        net.Conn
	destination M.Socksaddr
}

type testHandler chan testAccepted

func (h testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h <- testAccepted{ctx, conn, destination}
}

func (h testHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func newTestService(t *testing.T, timeout time.Duration) (*Service[string], testHandler, testHandler) {
	t.Helper()
	handler, fallback := make(testHandler, 1), make(testHandler, 1)
	service := NewService[string](handler, fallback, logger.NOP())
	service.handshakeTimeout = timeout
	if err := service.UpdateUsers([]string{"alice"}, []string{"password"}); err != nil {
		t.Fatal(err)
	}
	return service, handler, fallback
}

func trojanRequest(password string, payload string) []byte {
	key := Key(password)
	request := buf.New()
	defer request.Release()
	request.Write(key[:])
	request.Write(CRLF)
	request.WriteByte(CommandTCP)
	M.SocksaddrSerializer.WriteAddrPort(request, M.ParseSocksaddr("example.com:443"))
	request.Write(CRLF)
	request.WriteString(payload)
	return bytes.Clone(request.Bytes())
}

// serve runs NewConnection on the server end of a pipe and sends every chunk
// as a separate write, like separate TLS records.
func serve(t *testing.T, service *Service[string], chunks ...[]byte) (net.Conn, chan error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	result := make(chan error, 1)
	go func() {
		result <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
	}()
	go func() {
		for _, chunk := range chunks {
			if _, err := client.Write(chunk); err != nil {
				return
			}
		}
	}()
	return client, result
}

func accepted(t *testing.T, accept testHandler, within time.Duration) testAccepted {
	t.Helper()
	select {
	case it := <-accept:
		return it
	case <-time.After(within):
		t.Fatal("connection not handed over in time")
		return testAccepted{}
	}
}

func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	defer conn.SetReadDeadline(time.Time{})
	data := make([]byte, n)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestServiceFragmentedRequest(t *testing.T) {
	service, handler, _ := newTestService(t, time.Second)
	request := trojanRequest("password", "hello")
	var chunks [][]byte
	for _, size := range []int{1, 20, 34, 2, 1, 3} {
		chunks = append(chunks, request[:size])
		request = request[size:]
	}
	chunks = append(chunks, request)
	serve(t, service, chunks...)
	it := accepted(t, handler, time.Second)
	if user, _ := auth.UserFromContext[string](it.ctx); user != "alice" {
		t.Fatalf("user %q", user)
	}
	if it.destination.String() != "example.com:443" {
		t.Fatalf("destination %s", it.destination)
	}
	if data := readN(t, it.conn, 5); string(data) != "hello" {
		t.Fatalf("payload %q", data)
	}
}

func TestServiceFallbackReplaysBytes(t *testing.T) {
	wrongKey := trojanRequest("wrong", "tail")
	for _, test := range []struct {
		name   string
		chunks [][]byte
	}{
		{"short text request", [][]byte{[]byte("GET / HTTP/1.0\r\n\r\n")}},
		{"incomplete text request", [][]byte{[]byte("GET /"), []byte("index.html")}},
		{"binary probe", [][]byte{{0x16, 0x03, 0x01, 0x00}, []byte("more")}},
		{"wrong key", [][]byte{wrongKey[:30], wrongKey[30:]}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A long timeout: bytes that cannot be a key go to the fallback at once.
			service, _, fallback := newTestService(t, time.Minute)
			serve(t, service, test.chunks...)
			it := accepted(t, fallback, time.Second)
			want := bytes.Join(test.chunks, nil)
			if data := readN(t, it.conn, len(want)); !bytes.Equal(data, want) {
				t.Fatalf("fallback got %q, want %q", data, want)
			}
		})
	}
}

func TestServiceFallbackAfterTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond
	for _, test := range []struct {
		name    string
		partial []byte
	}{
		{"silent", nil},
		{"partial key", []byte("0123456789abcdef")},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _, fallback := newTestService(t, timeout)
			client, _ := serve(t, service, test.partial)
			it := accepted(t, fallback, time.Second)
			if test.partial != nil {
				if data := readN(t, it.conn, len(test.partial)); !bytes.Equal(data, test.partial) {
					t.Fatalf("fallback got %q", data)
				}
			}
			// No second read budget after an authentication timeout. The
			// fallback sees EOF but can still send an HTTP error response.
			one := make([]byte, 1)
			if n, err := it.conn.Read(one); n != 0 || err != io.EOF {
				t.Fatalf("timed-out fallback read: %d %v", n, err)
			}
			go it.conn.Write([]byte("reply"))
			if data := readN(t, client, 5); string(data) != "reply" {
				t.Fatalf("fallback reply %q", data)
			}
		})
	}
}

func TestServiceAuthenticatedStall(t *testing.T) {
	service, handler, fallback := newTestService(t, 100*time.Millisecond)
	key := Key("password")
	_, result := serve(t, service, key[:])
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stalled header accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled header not bounded by the handshake deadline")
	}
	if len(handler) != 0 || len(fallback) != 0 {
		t.Fatal("stalled authenticated connection was handed over")
	}
}

func TestEarlyFallbackDoesNotRetainDeadline(t *testing.T) {
	service, _, fallback := newTestService(t, 50*time.Millisecond)
	client, _ := serve(t, service, []byte("GET /"))
	it := accepted(t, fallback, time.Second)
	readN(t, it.conn, 5)
	time.Sleep(100 * time.Millisecond)
	go client.Write([]byte("later"))
	if data := readN(t, it.conn, 5); string(data) != "later" {
		t.Fatalf("read %q", data)
	}
}
