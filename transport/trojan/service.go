package trojan

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

// for v2bx: bounds reading the request header, see NewConnection.
const DefaultHandshakeTimeout = 10 * time.Second

type Service[K comparable] struct {
	users            common.TypedValue[map[K][56]byte]
	keys             common.TypedValue[map[[56]byte]K]
	handler          Handler
	fallbackHandler  N.TCPConnectionHandlerEx
	logger           logger.ContextLogger
	handshakeTimeout time.Duration
}

func NewService[K comparable](handler Handler, fallbackHandler N.TCPConnectionHandlerEx, logger logger.ContextLogger) *Service[K] {
	service := &Service[K]{
		handler:          handler,
		fallbackHandler:  fallbackHandler,
		logger:           logger,
		handshakeTimeout: DefaultHandshakeTimeout,
	}
	service.users.Store(make(map[K][56]byte))
	service.keys.Store(make(map[[56]byte]K))
	return service
}

var ErrUserExists = E.New("user already exists")

func (s *Service[K]) UpdateUsers(userList []K, passwordList []string) error {
	users := make(map[K][56]byte)
	keys := make(map[[56]byte]K)
	for i, user := range userList {
		if _, loaded := users[user]; loaded {
			return ErrUserExists
		}
		key := Key(passwordList[i])
		if oldUser, loaded := keys[key]; loaded {
			return E.Extend(ErrUserExists, "password used by ", oldUser)
		}
		users[user] = key
		keys[key] = user
	}
	s.users.Store(users)
	s.keys.Store(keys)
	return nil
}

// for v2bx: Contains reports whether user is in the current user list.
func (s *Service[K]) Contains(user K) bool {
	_, loaded := s.users.Load()[user]
	return loaded
}

// for v2bx: the key is read from a byte stream, independently of TLS record
// and TCP read boundaries, and the whole request header is read under one
// deadline that is cleared before the connection reaches the fallback or the
// handler. Unauthenticated bytes, including a partial read ending with EOF or
// timeout, are all replayed to the fallback.
func (s *Service[K]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(s.handshakeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	err := conn.SetReadDeadline(deadline)
	if err != nil {
		return E.Cause(err, "set handshake deadline")
	}
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		conn.SetReadDeadline(time.Now())
		close(canceled)
	})
	key := buf.NewSize(KeyLength)
	var (
		user        K
		command     byte
		destination M.Socksaddr
	)
	authenticated, err := func() (bool, error) {
		for !key.IsFull() {
			_, readErr := key.ReadOnceFrom(conn)
			if readErr != nil {
				return false, readErr
			}
			if !key.IsFull() && !isKeyPrefix(key.Bytes()) {
				return false, errNotKey
			}
		}
		var loaded bool
		user, loaded = s.keys.Load()[[KeyLength]byte(key.Bytes())]
		if !loaded {
			return false, E.New("unknown key")
		}
		readErr := rw.SkipN(conn, 2)
		if readErr != nil {
			return true, E.Cause(readErr, "skip crlf")
		}
		readErr = binary.Read(conn, binary.BigEndian, &command)
		if readErr != nil {
			return true, E.Cause(readErr, "read command")
		}
		switch command {
		case CommandTCP, CommandUDP, CommandMux:
		default:
			return true, E.New("unknown command ", command)
		}
		destination, readErr = M.SocksaddrSerializer.ReadAddrPort(conn)
		if readErr != nil {
			return true, E.Cause(readErr, "read destination")
		}
		readErr = rw.SkipN(conn, 2)
		if readErr != nil {
			return true, E.Cause(readErr, "skip crlf")
		}
		return true, nil
	}()
	// Synchronize an already-running cancellation callback before removing the
	// deadline, so it never leaves an expired deadline on a fallback or proxy.
	if !stopCancellation() {
		<-canceled
	}
	clearErr := conn.SetReadDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		key.Release()
		return ctxErr
	}
	if clearErr != nil {
		key.Release()
		return E.Cause(clearErr, "clear handshake deadline")
	}
	if !authenticated {
		// The cached connection owns a reference until drained or closed.
		cachedConn := bufio.NewCachedConn(conn, key)
		key.Release()
		return s.fallback(ctx, cachedConn, source, E.Cause(err, "bad request"), onClose)
	}
	key.Release()
	if err != nil {
		return err
	}
	ctx = auth.ContextWithUser(ctx, user)
	switch command {
	case CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, destination, onClose)
	case CommandUDP:
		s.handler.NewPacketConnectionEx(ctx, &PacketConn{Conn: conn}, source, destination, onClose)
	// case CommandMux:
	default:
		return HandleMuxConnection(ctx, conn, source, s.handler, s.logger, onClose)
	}
	return nil
}

func (s *Service[K]) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		conn.Close()
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

var errNotKey = E.New("not a trojan key")

// for v2bx: isKeyPrefix reports whether data can still grow into a key. Keys
// are lowercase hex digests, so any other byte, such as "GET /" or a TLS or
// binary probe, rules out every key and is handed to the fallback at once,
// as before. Only the public key format is inspected, never a password: an
// early rejection by matching prefixes would expose an oracle.
func isKeyPrefix(data []byte) bool {
	for _, c := range data {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type PacketConn struct {
	net.Conn
	readWaitOptions N.ReadWaitOptions
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return ReadPacket(c.Conn, buffer)
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return WritePacket(c.Conn, buffer, destination)
}

func (c *PacketConn) FrontHeadroom() int {
	return M.MaxSocksaddrLength + 4
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.Conn
}
