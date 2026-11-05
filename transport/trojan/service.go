package trojan

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

// for v2bx: bounds reading the request header, see NewConnection.
const DefaultHandshakeTimeout = 10 * time.Second

// DefaultFallbackHandshakeTimeout is the initial request-header budget when a
// web fallback is enabled. The built-in V2bX site uses the same budget.
const DefaultFallbackHandshakeTimeout = 30 * time.Second

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
	if fallbackHandler != nil {
		service.handshakeTimeout = DefaultFallbackHandshakeTimeout
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
// deadline. Unauthenticated bytes, including a partial read ending with EOF or
// timeout, are all replayed to the fallback, which inherits what is left of
// that deadline until the request head is complete (see fallbackConn).
func (s *Service[K]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// WebSocket, gRPC and HTTP/2 transport connections cannot set read
	// deadlines and fail with os.ErrInvalid; read them through a deadline
	// reader so the handshake stays bounded instead of being refused.
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	headerDeadline := time.Now().Add(s.handshakeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(headerDeadline) {
		headerDeadline = contextDeadline
	}
	err := conn.SetReadDeadline(headerDeadline)
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
		readErr := readCRLF(conn)
		if readErr != nil {
			return true, readErr
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
		readErr = readCRLF(conn)
		if readErr != nil {
			return true, readErr
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
		fallbackConn, budgetErr := newFallbackConn(conn, key.Bytes(), headerDeadline, E.IsTimeout(err))
		if budgetErr != nil {
			key.Release()
			return E.Cause(budgetErr, "set fallback deadline")
		}
		// The cached connection owns a reference until drained or closed.
		cachedConn := bufio.NewCachedConn(fallbackConn, key)
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

// for v2bx: fallbackConn gives the fallback what is left of the request-header
// deadline instead of a fresh wait. A web server counts its header timeout
// from the start of the connection; without this, a probe could send a few
// hex digits, break the key format just before the deadline, and get a second
// full header wait from the fallback, a timing difference to a plain server.
//
// Until the client completes a request head, reads stay bounded by the
// handshake deadline. When it passes, the read side ends with EOF, as if the
// client had stopped sending, and the write side stays open so the fallback
// can still reply. Once the head is complete the fallback's own timeouts take
// over, so keep-alive, uploads and HTTP/2 streams are not cut short.
type fallbackConn struct {
	net.Conn
	access   sync.Mutex
	budget   time.Time // zero once the request head is complete
	deadline time.Time // the fallback's own read deadline
	expired  bool
	head     headScanner
}

// newFallbackConn returns conn unchanged when the replayed bytes already hold
// a complete request head, so ordinary requests are forwarded untouched.
func newFallbackConn(conn net.Conn, cached []byte, budget time.Time, timedOut bool) (net.Conn, error) {
	var head headScanner
	if !timedOut && head.scan(cached) {
		return conn, nil
	}
	fallbackConn := &fallbackConn{Conn: conn, budget: budget, head: head}
	if timedOut || !time.Now().Before(budget) {
		fallbackConn.expired = true
		return fallbackConn, nil
	}
	return fallbackConn, conn.SetReadDeadline(budget)
}

func (c *fallbackConn) Read(p []byte) (int, error) {
	c.access.Lock()
	expired, pending := c.expired, !c.budget.IsZero()
	c.access.Unlock()
	if expired {
		return 0, io.EOF
	}
	n, err := c.Conn.Read(p)
	if !pending {
		return n, err
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.budget.IsZero() {
		return n, err
	}
	if c.head.scan(p[:n]) {
		c.budget = time.Time{}
		if deadlineErr := c.Conn.SetReadDeadline(c.deadline); err == nil {
			err = deadlineErr
		}
		return n, err
	}
	if E.IsTimeout(err) && (c.deadline.IsZero() || !c.deadline.Before(c.budget) || !time.Now().Before(c.budget)) {
		c.expired = true
		return n, io.EOF
	}
	return n, err
}

// SetReadDeadline keeps the budget in force while the head is incomplete: a
// deadline set by the fallback path, or clearing it, cannot extend the wait.
func (c *fallbackConn) SetReadDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.deadline = t
	if !c.budget.IsZero() && !c.expired && (t.IsZero() || c.budget.Before(t)) {
		t = c.budget
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *fallbackConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

// Upstream preserves TLS/ALPN discovery through connection wrappers. Reads
// stay on this wrapper until the head is complete: bypassing it would lose the
// EOF and let a cleared deadline restart the wait.
func (c *fallbackConn) Upstream() any { return c.Conn }

func (c *fallbackConn) ReaderReplaceable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.budget.IsZero() && !c.expired
}

func (c *fallbackConn) WriterReplaceable() bool { return true }

// headScanner looks for the blank line that ends an HTTP/1 request head:
// CRLF CRLF, or the bare LF LF that web servers accept as well. The HTTP/2
// client preface contains one too.
type headScanner uint8

const (
	headLineStart headScanner = iota + 1 // after LF
	headLineCR                           // after LF CR
)

func (s *headScanner) scan(data []byte) bool {
	state := *s
	for _, c := range data {
		switch {
		case c == '\n' && state != 0:
			*s = 0
			return true
		case c == '\n':
			state = headLineStart
		case c == '\r' && state == headLineStart:
			state = headLineCR
		default:
			state = 0
		}
	}
	*s = state
	return false
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
