package tlsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type alpnKey struct{}

func ContextWithALPN(ctx context.Context, alpn string) context.Context {
	return context.WithValue(ctx, alpnKey{}, alpn)
}

func ALPN(ctx context.Context) string {
	value, _ := ctx.Value(alpnKey{}).(string)
	return value
}

// Validate protects the plaintext boundary behind the local TLS terminator.
func Validate(address netip.Addr, tlsEnabled bool, transport string) error {
	if !address.IsLoopback() || tlsEnabled || transport != "" {
		return fmt.Errorf("trusted TLS proxy requires a loopback listener without TLS or transport")
	}
	return nil
}

// HAProxy sends the original peer and negotiated ALPN in PROXY v2. This is
// deliberately not a general public PROXY listener: only loopback peers are
// trusted, and plain TCP, LOCAL, datagrams and unbounded TLVs are rejected.
func Read(conn net.Conn) (source M.Socksaddr, alpn string, err error) {
	peer := M.SocksaddrFromNet(conn.RemoteAddr())
	if !peer.Addr.IsLoopback() {
		return source, "", fmt.Errorf("TLS proxy peer must be loopback")
	}
	if err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	defer func() {
		if clearErr := conn.SetReadDeadline(time.Time{}); err == nil {
			err = clearErr
		}
	}()
	var header [16]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(header[14:]))
	if !bytes.Equal(header[:12], []byte("\r\n\r\n\x00\r\nQUIT\n")) || header[12] != 0x21 || length > 4096 {
		err = fmt.Errorf("invalid TLS proxy header")
		return
	}
	payload := make([]byte, length)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return
	}
	var offset int
	switch header[13] {
	case 0x11:
		if length >= 12 {
			source = M.SocksaddrFrom(netip.AddrFrom4([4]byte(payload[:4])), binary.BigEndian.Uint16(payload[8:10]))
			offset = 12
		}
	case 0x21:
		if length >= 36 {
			source = M.SocksaddrFrom(netip.AddrFrom16([16]byte(payload[:16])).Unmap(), binary.BigEndian.Uint16(payload[32:34]))
			offset = 36
		}
	}
	if offset == 0 {
		err = fmt.Errorf("TLS proxy requires a TCP IPv4 or IPv6 address")
		return
	}
	for offset < length {
		if length-offset < 3 {
			err = fmt.Errorf("truncated TLS proxy TLV")
			return
		}
		kind, size := payload[offset], int(binary.BigEndian.Uint16(payload[offset+1:offset+3]))
		offset += 3
		if size > length-offset {
			err = fmt.Errorf("truncated TLS proxy TLV value")
			return
		}
		if kind == 1 {
			alpn = string(payload[offset : offset+size])
			if alpn != "" && alpn != "h2" && alpn != "http/1.1" {
				err = fmt.Errorf("unsupported TLS proxy ALPN")
				return
			}
		}
		offset += size
	}
	return
}
