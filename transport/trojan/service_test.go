package trojan

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
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
	return serveConn(t, service, func(conn net.Conn) net.Conn { return conn }, chunks...)
}

func serveConn(t *testing.T, service *Service[string], wrap func(net.Conn) net.Conn, chunks ...[]byte) (net.Conn, chan error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	result := make(chan error, 1)
	go func() {
		result <- service.NewConnection(context.Background(), wrap(server), M.Socksaddr{}, nil)
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

// readOne reads one byte and fails the test instead of hanging when the read
// is not ended within a few seconds.
func readOne(t *testing.T, conn net.Conn) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := conn.Read(make([]byte, 1))
		done <- result{n, err}
	}()
	select {
	case it := <-done:
		return it.n, it.err
	case <-time.After(3 * time.Second):
		conn.Close()
		t.Fatal("read not ended")
		return 0, nil
	}
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

// A probe that sends hex digits and breaks the key format just before the
// deadline must not get a second full header wait from the fallback: the
// fallback read side ends when the original deadline passes.
func TestFallbackSharesHeaderBudget(t *testing.T) {
	const timeout = 500 * time.Millisecond
	service, _, fallback := newTestService(t, timeout)
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	start := time.Now()
	go service.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
	client.Write([]byte("0123"))
	time.Sleep(350 * time.Millisecond)
	go client.Write([]byte("X"))
	it := accepted(t, fallback, time.Second)
	if data := readN(t, it.conn, 5); string(data) != "0123X" {
		t.Fatalf("fallback got %q", data)
	}
	if n, err := readOne(t, it.conn); n != 0 || err != io.EOF {
		t.Fatalf("fallback read after budget: %d %v", n, err)
	}
	if elapsed := time.Since(start); elapsed < timeout-50*time.Millisecond || elapsed > timeout+250*time.Millisecond {
		t.Fatalf("fallback read ended after %s, want about %s", elapsed, timeout)
	}
	go it.conn.Write([]byte("reply"))
	if data := readN(t, client, 5); string(data) != "reply" {
		t.Fatalf("fallback reply %q", data)
	}
}

// Once the request head is complete, the fallback's own timeouts apply:
// keep-alive requests are not cut at the handshake deadline.
func TestFallbackHeadCompletionLiftsBudget(t *testing.T) {
	const timeout = 50 * time.Millisecond
	for _, test := range []struct {
		name   string
		first  string
		second string
	}{
		{"head in replayed bytes", "GET / HTTP/1.0\r\n\r\n", ""},
		{"head across reads", "GET /", " HTTP/1.1\r\nHost: a\r\n\r\n"},
		{"bare LF head", "GET /", " HTTP/1.1\nHost: a\n\n"},
		{"HTTP/2 preface", "PRI * HTTP/2.0\r\n", "\r\nSM\r\n\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _, fallback := newTestService(t, timeout)
			client, _ := serve(t, service, []byte(test.first))
			it := accepted(t, fallback, time.Second)
			readN(t, it.conn, len(test.first))
			if test.second != "" {
				go client.Write([]byte(test.second))
				readN(t, it.conn, len(test.second))
			}
			time.Sleep(2 * timeout)
			go client.Write([]byte("later"))
			if data := readN(t, it.conn, 5); string(data) != "later" {
				t.Fatalf("read %q", data)
			}
		})
	}
}

// Deadlines set on the fallback connection, such as a sniffer clearing its
// own, cannot extend the budget; an earlier deadline still times out normally.
func TestFallbackDeadlineCannotExtendBudget(t *testing.T) {
	const timeout = 300 * time.Millisecond
	service, _, fallback := newTestService(t, timeout)
	_, _ = serve(t, service, []byte("GET /"))
	it := accepted(t, fallback, time.Second)
	readN(t, it.conn, 5)
	one := make([]byte, 1)
	it.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := it.conn.Read(one); err == io.EOF || !E.IsTimeout(err) {
		t.Fatalf("early deadline: %v", err)
	}
	it.conn.SetReadDeadline(time.Time{})
	start := time.Now()
	if n, err := readOne(t, it.conn); n != 0 || err != io.EOF {
		t.Fatalf("read after clearing deadline: %d %v", n, err)
	}
	if elapsed := time.Since(start); elapsed > timeout {
		t.Fatalf("budget extended: read ended after %s", elapsed)
	}
}

// WebSocket, gRPC and HTTP/2 transport connections reject SetReadDeadline.
type noDeadlineConn struct{ net.Conn }

func (c noDeadlineConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (c noDeadlineConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (c noDeadlineConn) NeedAdditionalReadDeadline() bool { return true }

func TestServiceTransportWithoutDeadline(t *testing.T) {
	wrap := func(conn net.Conn) net.Conn { return noDeadlineConn{conn} }
	t.Run("accepted", func(t *testing.T) {
		service, handler, _ := newTestService(t, time.Second)
		serveConn(t, service, wrap, trojanRequest("password", "hello"))
		it := accepted(t, handler, time.Second)
		if data := readN(t, it.conn, 5); string(data) != "hello" {
			t.Fatalf("payload %q", data)
		}
	})
	t.Run("stall bounded", func(t *testing.T) {
		service, _, fallback := newTestService(t, 100*time.Millisecond)
		serveConn(t, service, wrap, []byte("0123"))
		it := accepted(t, fallback, time.Second)
		readN(t, it.conn, 4)
		one := make([]byte, 1)
		if n, err := it.conn.Read(one); n != 0 || err != io.EOF {
			t.Fatalf("timed-out fallback read: %d %v", n, err)
		}
	})
}

func TestServiceRejectsBadCRLF(t *testing.T) {
	request := trojanRequest("password", "hello")
	addressEnd := len(request) - len("hello") - 2
	for _, test := range []struct {
		name string
		at   int
	}{
		{"after key", KeyLength},
		{"after destination", addressEnd},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, handler, fallback := newTestService(t, time.Second)
			bad := bytes.Clone(request)
			copy(bad[test.at:], "XX")
			_, result := serve(t, service, bad)
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("bad separator accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("bad separator not rejected")
			}
			if len(handler) != 0 || len(fallback) != 0 {
				t.Fatal("bad separator handed over")
			}
		})
	}
}

func TestReadPacketRejectsBadCRLF(t *testing.T) {
	frame := func(separator string) []byte {
		packet := buf.New()
		defer packet.Release()
		M.SocksaddrSerializer.WriteAddrPort(packet, M.ParseSocksaddr("1.1.1.1:53"))
		packet.Write([]byte{0, 4})
		packet.WriteString(separator)
		packet.WriteString("ping")
		return bytes.Clone(packet.Bytes())
	}
	read := map[string]func(net.Conn) (*buf.Buffer, error){
		"ReadPacket": func(conn net.Conn) (*buf.Buffer, error) {
			buffer := buf.New()
			_, err := ReadPacket(conn, buffer)
			return buffer, err
		},
		"WaitReadPacket": func(conn net.Conn) (*buf.Buffer, error) {
			packetConn := &PacketConn{Conn: conn}
			packetConn.InitializeReadWaiter(N.ReadWaitOptions{})
			buffer, _, err := packetConn.WaitReadPacket()
			return buffer, err
		},
	}
	for name, readFrame := range read {
		for _, separator := range []string{"\r\n", "XX"} {
			client, server := net.Pipe()
			go client.Write(frame(separator))
			server.SetReadDeadline(time.Now().Add(time.Second))
			buffer, err := readFrame(server)
			if separator == "\r\n" && (err != nil || string(buffer.Bytes()) != "ping") {
				t.Fatalf("%s: valid frame: %v", name, err)
			}
			if separator != "\r\n" && err == nil {
				t.Fatalf("%s: bad separator accepted", name)
			}
			if buffer != nil {
				buffer.Release()
			}
			client.Close()
			server.Close()
		}
	}
}
