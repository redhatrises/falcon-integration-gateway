package workspaceone

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testServerTLSConfig builds a self-signed TLS 1.2 server config for the test
// syslog listener. The client uses InsecureSkipVerify, so the cert need not
// chain to any CA.
func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workspaceone-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

// testSyslogServer is a minimal TLS listener that reads NUL-terminated frames
// from each accepted connection and publishes them on received. It reads in a
// loop so one connection can carry many frames, and counts accepted connections
// so tests can prove the sender reuses a single connection.
type testSyslogServer struct {
	addr     string
	received chan []byte
	conns    atomic.Int64
}

func newTestSyslogServer(t *testing.T) *testSyslogServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testServerTLSConfig(t))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &testSyslogServer{addr: ln.Addr().String(), received: make(chan []byte, 64)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					frame, err := r.ReadBytes(0x00)
					if err != nil {
						return
					}
					s.received <- frame
				}
			}(conn)
		}
	}()
	return s
}

func (s *testSyslogServer) waitFrame(t *testing.T) []byte {
	t.Helper()
	select {
	case f := <-s.received:
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func newTestSender(addr string) *tlsSender {
	return newTLSSender(tlsSenderInput{
		addr:         addr,
		tlsConfig:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, //nolint:gosec // test client accepts the self-signed server cert
		dialTimeout:  3 * time.Second,
		writeTimeout: 3 * time.Second,
	})
}

func TestTLSSenderSendsFramedBytes(t *testing.T) {
	t.Parallel()
	srv := newTestSyslogServer(t)
	s := newTestSender(srv.addr)
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	payload := []byte("<14>hello\x00")
	if err := s.send(context.Background(), payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	got := srv.waitFrame(t)
	if string(got) != string(payload) {
		t.Errorf("server received %q, want %q", got, payload)
	}
}

func TestTLSSenderReusesConnection(t *testing.T) {
	t.Parallel()
	srv := newTestSyslogServer(t)
	s := newTestSender(srv.addr)
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	frames := [][]byte{
		[]byte("<14>one\x00"),
		[]byte("<14>two\x00"),
		[]byte("<14>three\x00"),
	}
	for _, f := range frames {
		if err := s.send(context.Background(), f); err != nil {
			t.Fatalf("send %q: %v", f, err)
		}
		if got := srv.waitFrame(t); string(got) != string(f) {
			t.Fatalf("frame %q, want %q", got, f)
		}
	}

	// All three frames rode one lazily-dialed connection: the sender must not
	// re-dial per write.
	if n := srv.conns.Load(); n != 1 {
		t.Errorf("server accepted %d connections, want 1 (connection not reused)", n)
	}
}

func TestTLSSenderConcurrentSends(t *testing.T) {
	t.Parallel()
	srv := newTestSyslogServer(t)
	s := newTestSender(srv.addr)
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	const goroutines = 16
	want := make([]string, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		payload := fmt.Sprintf("<14>frame-%02d\x00", i)
		want[i] = payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.send(context.Background(), []byte(payload)); err != nil {
				t.Errorf("concurrent send: %v", err)
			}
		}()
	}
	wg.Wait()

	got := make([]string, 0, goroutines)
	for range want {
		got = append(got, string(srv.waitFrame(t)))
	}
	sort.Strings(got)
	sort.Strings(want)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("frame %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTLSSenderReconnectsAfterClose(t *testing.T) {
	t.Parallel()
	srv := newTestSyslogServer(t)
	s := newTestSender(srv.addr)
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	first := []byte("<14>first\x00")
	if err := s.send(context.Background(), first); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if got := srv.waitFrame(t); string(got) != string(first) {
		t.Fatalf("first frame %q, want %q", got, first)
	}

	// Closing drops the connection; the next send must lazily re-dial.
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := []byte("<14>second\x00")
	if err := s.send(context.Background(), second); err != nil {
		t.Fatalf("second send: %v", err)
	}
	if got := srv.waitFrame(t); string(got) != string(second) {
		t.Errorf("second frame %q, want %q", got, second)
	}
}

// errConn fails every Write, to exercise the reconnect-on-error path.
type errConn struct {
	net.Conn
}

func (errConn) Write([]byte) (int, error)        { return 0, errors.New("write boom") }
func (errConn) Close() error                     { return nil }
func (errConn) SetWriteDeadline(time.Time) error { return nil }

func TestTLSSenderWriteErrorNullsConn(t *testing.T) {
	t.Parallel()
	s := newTestSender("127.0.0.1:0")
	s.conn = errConn{}

	err := s.send(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("expected send to return the write error")
	}
	if s.conn != nil {
		t.Error("failed write must null the connection so the next send re-dials")
	}
}

func TestTLSSenderCloseWithoutConn(t *testing.T) {
	t.Parallel()
	s := newTestSender("127.0.0.1:0")
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("Close with no open connection must be a no-op, got %v", err)
	}
}

func TestTLSSenderDialErrorWrapped(t *testing.T) {
	t.Parallel()
	// Nothing is listening on this address; the dial must fail and be wrapped.
	s := newTLSSender(tlsSenderInput{
		addr:         "127.0.0.1:1",
		tlsConfig:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, //nolint:gosec // test client accepts the self-signed server cert
		dialTimeout:  500 * time.Millisecond,
		writeTimeout: 500 * time.Millisecond,
	})
	err := s.send(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("expected dial error")
	}
}
