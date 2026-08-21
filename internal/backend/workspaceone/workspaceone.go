// Package workspaceone forwards Falcon detection events to VMware Workspace ONE
// Intelligence as CEF (Common Event Format) records over a TLS syslog stream.
//
// Each EppDetectionSummaryEvent whose host resolves to an MDM identifier is
// rendered to a CEF string, framed as one NUL-terminated syslog record, and
// written to a single shared TLS connection. The wire format is fixed by what
// Workspace ONE Intelligence ingests: the field order is stable and CEF values
// are emitted without escaping.
//
// # Throughput and ordering
//
// All workers share one TLS connection and their writes are serialized under a
// mutex. This mirrors the reference deployment, whose Python logging handler
// held a lock around each emit, and is required for correctness rather than
// convenience: interleaved writes on one stream would corrupt the NUL framing.
// The connection is dialed lazily on the first delivered event and reused for
// the process lifetime; a write error drops it so the next send re-dials.
// Delivery is at-least-once — a write can succeed on the wire yet be reported
// as failed (e.g. deadline after the bytes flush), and the pipeline then
// retries, so the receiver may observe an occasional duplicate record.
//
// # Transport security
//
// TLS is pinned to exactly 1.2 (PROTOCOL_TLSv1_2). Certificate verification is
// off by default, matching the reference deployment's syslog receiver
// (CERT_NONE), and is enabled by setting workspaceone.tls_verify. The Workspace
// ONE ingest token is carried in the CEF payload itself (the Token= field), so
// with verification disabled a network attacker who can impersonate the syslog
// host could capture that token; operators reaching a receiver that presents a
// valid certificate should set tls_verify to close that gap. The default stays
// off for parity, not as a recommendation. The toggle governs verification
// only; raising MaxVersion above 1.2 is a separate future hardening. The token
// is a secret and is never logged.
package workspaceone

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// backendName is the registry key and Name() value for this backend.
const backendName = "WORKSPACEONE"

// threadNameLabel is emitted in the syslog framing prefix in the position that
// historically held a worker thread name. The receiver scans for "CEF:" and
// ignores the prefix, so a fixed label preserves the wire shape without claiming
// a thread identity that does not exist here.
const threadNameLabel = "fig"

// dialTimeout and writeTimeout bound the TLS connection and each write so a
// stalled syslog endpoint cannot block a worker indefinitely.
const (
	dialTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

// Runtime forwards detection summaries to Workspace ONE Intelligence as CEF
// records over a shared, lazily-dialed TLS syslog connection.
type Runtime struct {
	logger     *slog.Logger
	token      string
	send       sender
	now        func() time.Time
	threadName string
}

// New constructs the Workspace ONE backend. It builds the TLS sender from the
// configured host, port, and token but does not dial: the connection opens on
// the first delivered event. TLS is pinned to 1.2; certificate verification is
// off by default to match the reference deployment's syslog receiver and is
// enabled by setting workspaceone.tls_verify.
func New(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	wc := cfg.WorkspaceOne
	addr := net.JoinHostPort(wc.SyslogHost, strconv.Itoa(wc.SyslogPort))
	s := newTLSSender(tlsSenderInput{
		addr: addr,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: !wc.TLSVerify, //nolint:gosec // verification is opt-in via workspaceone.tls_verify; default off for parity, see package docs
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		},
		dialTimeout:  dialTimeout,
		writeTimeout: writeTimeout,
	})
	logger.Info("WORKSPACEONE backend is enabled.", "syslog_addr", addr, "tls_verify", wc.TLSVerify)
	return &Runtime{
		logger:     logger,
		token:      wc.Token,
		send:       s,
		now:        time.Now,
		threadName: threadNameLabel,
	}, nil
}

// Name returns the backend registry identifier.
func (r *Runtime) Name() string {
	return backendName
}

// RelevantEventTypes narrows the server-side stream filter to detection
// summaries, the only family this backend forwards.
func (r *Runtime) RelevantEventTypes() []string {
	return []string{cefEventType}
}

// IsRelevant reports whether the event's host has a resolvable MDM identifier,
// which becomes the CEF UDID. An empty identifier or a lookup error means the
// device is not enrolled (or cannot be resolved), so the event is dropped.
func (r *Runtime) IsRelevant(ctx context.Context, ev *events.EnrichedEvent) bool {
	id, err := ev.MDMIdentifier(ctx)
	if err != nil {
		r.logger.Debug("WORKSPACEONE dropping event: MDM identifier lookup failed",
			"uid", ev.UID(), "error", err)
		return false
	}
	return id != ""
}

// Process resolves the MDM identifier, builds the CEF record, frames it for
// syslog, and writes it to the shared TLS connection. This repeats the lookup
// IsRelevant already performed; the enricher's own per-sensor cache absorbs it,
// so the second call does not open another RTR session. A resolution or
// delivery error is returned wrapped so the pipeline can retry.
func (r *Runtime) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	udid, err := ev.MDMIdentifier(ctx)
	if err != nil {
		return fmt.Errorf("workspaceone: resolve MDM identifier for %s: %w", ev.UID(), err)
	}

	cef := buildCEF(cefInput{ev: ev.Event, token: r.token, udid: udid, eventID: ev.EventID(), dedupKey: ev.DedupKey()})
	payload := frame(frameInput{cef: cef, now: r.now(), threadName: r.threadName})

	if err := r.send.send(ctx, payload); err != nil {
		return fmt.Errorf("workspaceone: send event %s: %w", ev.UID(), err)
	}
	return nil
}

// Close closes the underlying TLS connection. It satisfies backend.Closer.
func (r *Runtime) Close(ctx context.Context) error {
	if r.send == nil {
		return nil
	}
	return r.send.Close(ctx)
}

func init() {
	backend.Register(backendName, New)
}
