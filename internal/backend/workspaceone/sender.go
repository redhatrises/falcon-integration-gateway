package workspaceone

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// sender delivers a framed CEF record to the Workspace ONE syslog endpoint.
// It is a small consumer-side interface so the Runtime can be tested with a
// fake that captures payloads.
type sender interface {
	send(ctx context.Context, payload []byte) error
	Close(ctx context.Context) error
}

// tlsSenderInput carries the construction parameters for a tlsSender.
type tlsSenderInput struct {
	addr         string
	tlsConfig    *tls.Config
	dialTimeout  time.Duration
	writeTimeout time.Duration
}

// tlsSender ships framed records over a single persistent TLS connection.
// Workers share one sender, so writes are serialized under mu: interleaved
// writes would corrupt the NUL-terminated framing. The connection is dialed
// lazily on the first send and re-dialed after any I/O error.
type tlsSender struct {
	addr         string
	tlsConfig    *tls.Config
	dialTimeout  time.Duration
	writeTimeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func newTLSSender(in tlsSenderInput) *tlsSender {
	return &tlsSender{
		addr:         in.addr,
		tlsConfig:    in.tlsConfig,
		dialTimeout:  in.dialTimeout,
		writeTimeout: in.writeTimeout,
	}
}

// send writes one framed payload, dialing the TLS connection if it is not yet
// open. Any dial or write error closes and nils the connection so the next
// send reconnects, and is returned wrapped so the pipeline can retry.
func (s *tlsSender) send(ctx context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		conn, err := s.dial(ctx)
		if err != nil {
			return fmt.Errorf("workspaceone: dial %s: %w", s.addr, err)
		}
		s.conn = conn
	}

	if s.writeTimeout > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
			s.dropConn()
			return fmt.Errorf("workspaceone: set write deadline: %w", err)
		}
	}

	if _, err := s.conn.Write(payload); err != nil {
		s.dropConn()
		return fmt.Errorf("workspaceone: write to %s: %w", s.addr, err)
	}
	return nil
}

func (s *tlsSender) dial(ctx context.Context) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: s.dialTimeout},
		Config:    s.tlsConfig,
	}
	return dialer.DialContext(ctx, "tcp", s.addr)
}

// dropConn closes and nils the connection so the next send re-dials. The
// caller must hold mu.
func (s *tlsSender) dropConn() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// Close closes the underlying connection if one is open. It is safe to call
// with no connection established.
func (s *tlsSender) Close(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	if err != nil {
		return fmt.Errorf("workspaceone: close connection: %w", err)
	}
	return nil
}
