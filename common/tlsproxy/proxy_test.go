package tlsproxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
)

func TestValidateTLSProxyBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, address, transport string
		tls, valid               bool
	}{
		{"loopback", "127.0.0.1", "", false, true},
		{"IPv6 loopback", "::1", "", false, true},
		{"public bind", "0.0.0.0", "", false, false},
		{"double TLS", "127.0.0.1", "", true, false},
		{"WebSocket", "127.0.0.1", "ws", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(netip.MustParseAddr(tc.address), tc.tls, tc.transport); (err == nil) != tc.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

type proxyPeerConn struct {
	net.Conn
	peer net.Addr
}

func (c proxyPeerConn) RemoteAddr() net.Addr { return c.peer }

func TestTLSProxyPreservesSourceALPNAndPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	payload := []byte{203, 0, 113, 5, 127, 0, 0, 1, 0x87, 0x07, 1, 0xbb, 1, 0, 2, 'h', '2'}
	header := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, byte(len(payload)))
	go client.Write(append(append(header, payload...), []byte("payload")...))
	source, alpn, err := Read(proxyPeerConn{server, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}})
	if err != nil || source.String() != "203.0.113.5:34567" || alpn != "h2" {
		t.Fatalf("source=%s alpn=%q err=%v", source, alpn, err)
	}
	tail := make([]byte, 7)
	if _, err = io.ReadFull(server, tail); err != nil || string(tail) != "payload" {
		t.Fatalf("payload %q %v", tail, err)
	}
}

func TestTLSProxyRejectsPublicPeerAndOversizedHeader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, _, err := Read(proxyPeerConn{server, &net.TCPAddr{IP: net.ParseIP("203.0.113.1")}}); err == nil {
		t.Fatal("public peer trusted")
	}
	header := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 0)
	binary.BigEndian.PutUint16(header[14:], 4097)
	go client.Write(header)
	if _, _, err := Read(proxyPeerConn{server, &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}); err == nil {
		t.Fatal("oversized header accepted")
	}
}
