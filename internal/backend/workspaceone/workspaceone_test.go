package workspaceone

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// wsEnricher resolves host details and an MDM identifier for events under test.
type wsEnricher struct {
	platform string
	mdm      string
	mdmErr   error
	hostErr  error
}

func (f *wsEnricher) HostDetails(_ context.Context, _ string) (*common.HostDetails, error) {
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	return &common.HostDetails{Platform: f.platform}, nil
}

func (f *wsEnricher) MDMIdentifier(_ context.Context, _, _ string) (string, error) {
	return f.mdm, f.mdmErr
}

func (f *wsEnricher) ArcConfig(_ context.Context, _, _ string) (*events.ArcConfig, error) {
	return nil, nil
}

// fakeSender captures the framed payloads Process hands it.
type fakeSender struct {
	payloads [][]byte
	err      error
	closed   bool
}

func (f *fakeSender) send(_ context.Context, p []byte) error {
	if f.err != nil {
		return f.err
	}
	f.payloads = append(f.payloads, append([]byte(nil), p...))
	return nil
}

func (f *fakeSender) Close(_ context.Context) error {
	f.closed = true
	return nil
}

func wsTestEvent(enricher events.Enricher) *events.EnrichedEvent {
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{EventType: cefEventType, Offset: 5, EventCreationTime: 1620000000000},
		Event:    map[string]any{"SensorId": "sensor-1", "UserName": "alice"},
	}, enricher)
}

func TestName(t *testing.T) {
	t.Parallel()
	rt := &Runtime{logger: testutil.DiscardLogger()}
	if rt.Name() != backendName {
		t.Errorf("Name() = %q, want %q", rt.Name(), backendName)
	}
}

func TestRelevantEventTypes(t *testing.T) {
	t.Parallel()
	rt := &Runtime{logger: testutil.DiscardLogger()}
	got := rt.RelevantEventTypes()
	if len(got) != 1 || got[0] != cefEventType {
		t.Errorf("RelevantEventTypes() = %v, want [%q]", got, cefEventType)
	}
}

func TestIsRelevant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mdm    string
		mdmErr error
		want   bool
	}{
		{name: "mdm identifier present is relevant", mdm: "UDID-1", want: true},
		{name: "empty mdm identifier is not relevant", mdm: "", want: false},
		{name: "mdm lookup error is not relevant", mdmErr: errors.New("boom"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt := &Runtime{logger: testutil.DiscardLogger()}
			ev := wsTestEvent(&wsEnricher{mdm: tc.mdm, mdmErr: tc.mdmErr})
			if got := rt.IsRelevant(context.Background(), ev); got != tc.want {
				t.Errorf("IsRelevant = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProcessSendsFramedCEF(t *testing.T) {
	t.Parallel()
	fixedNow := time.Date(2026, 8, 14, 12, 30, 45, 0, time.UTC)
	fs := &fakeSender{}
	rt := &Runtime{
		logger:     testutil.DiscardLogger(),
		token:      "tok-abc",
		send:       fs,
		now:        func() time.Time { return fixedNow },
		threadName: "fig",
	}
	ev := wsTestEvent(&wsEnricher{mdm: "UDID-1"})

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(fs.payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(fs.payloads))
	}

	wantCEF := buildCEF(cefInput{ev: ev.Event, token: "tok-abc", udid: "UDID-1", eventID: ev.EventID(), dedupKey: ev.DedupKey()})
	want := frame(frameInput{cef: wantCEF, now: fixedNow, threadName: "fig"})
	if string(fs.payloads[0]) != string(want) {
		t.Errorf("payload mismatch\n got: %q\nwant: %q", fs.payloads[0], want)
	}
}

func TestProcessWrapsSendError(t *testing.T) {
	t.Parallel()
	sendErr := errors.New("delivery failed")
	rt := &Runtime{
		logger:     testutil.DiscardLogger(),
		token:      "tok",
		send:       &fakeSender{err: sendErr},
		now:        time.Now,
		threadName: "fig",
	}
	ev := wsTestEvent(&wsEnricher{mdm: "UDID-1"})

	err := rt.Process(context.Background(), ev)
	if err == nil {
		t.Fatal("expected Process to return the send error")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("error %v does not wrap %v", err, sendErr)
	}
}

func TestProcessMDMErrorReturnsError(t *testing.T) {
	t.Parallel()
	mdmErr := errors.New("mdm lookup failed")
	fs := &fakeSender{}
	rt := &Runtime{
		logger:     testutil.DiscardLogger(),
		token:      "tok",
		send:       fs,
		now:        time.Now,
		threadName: "fig",
	}
	ev := wsTestEvent(&wsEnricher{mdmErr: mdmErr})

	err := rt.Process(context.Background(), ev)
	if err == nil {
		t.Fatal("expected Process to return the MDM lookup error")
	}
	if !errors.Is(err, mdmErr) {
		t.Errorf("error %v does not wrap %v", err, mdmErr)
	}
	if len(fs.payloads) != 0 {
		t.Errorf("no payload should be sent when the MDM lookup fails, got %d", len(fs.payloads))
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	fs := &fakeSender{}
	rt := &Runtime{logger: testutil.DiscardLogger(), send: fs}
	if err := rt.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fs.closed {
		t.Error("Close must delegate to the sender")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		WorkspaceOne: config.WorkspaceOneConfig{
			Token:      "tok",
			SyslogHost: "syslog.example.com",
			SyslogPort: 6514,
		},
	}
	b, err := New(cfg, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Name() != backendName {
		t.Errorf("Name() = %q, want %q", b.Name(), backendName)
	}
	if _, ok := b.(backend.Closer); !ok {
		t.Error("New must return a backend.Closer")
	}
}

func TestNewTLSVerifyToggle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		tlsVerify      bool
		wantSkipVerify bool
	}{
		{name: "verification off by default preserves parity", tlsVerify: false, wantSkipVerify: true},
		{name: "verification opt-in enables cert checking", tlsVerify: true, wantSkipVerify: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				WorkspaceOne: config.WorkspaceOneConfig{
					Token:      "tok",
					SyslogHost: "syslog.example.com",
					SyslogPort: 6514,
					TLSVerify:  tc.tlsVerify,
				},
			}
			b, err := New(cfg, testutil.DiscardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			rt, ok := b.(*Runtime)
			if !ok {
				t.Fatalf("New returned %T, want *Runtime", b)
			}
			ts, ok := rt.send.(*tlsSender)
			if !ok {
				t.Fatalf("sender is %T, want *tlsSender", rt.send)
			}
			if ts.tlsConfig.InsecureSkipVerify != tc.wantSkipVerify {
				t.Errorf("InsecureSkipVerify = %v, want %v", ts.tlsConfig.InsecureSkipVerify, tc.wantSkipVerify)
			}
			if ts.tlsConfig.MinVersion != tls.VersionTLS12 || ts.tlsConfig.MaxVersion != tls.VersionTLS12 {
				t.Errorf("TLS version pinning = [min %d, max %d], want both %d regardless of toggle",
					ts.tlsConfig.MinVersion, ts.tlsConfig.MaxVersion, tls.VersionTLS12)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	t.Parallel()
	if !slices.Contains(backend.Names(), backendName) {
		t.Errorf("backend %q not registered; got %v", backendName, backend.Names())
	}
}
