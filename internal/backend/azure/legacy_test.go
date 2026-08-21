package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedTime is an arbitrary deterministic instant for signature assertions.
func fixedTime() time.Time {
	return time.Date(2026, 8, 14, 12, 34, 56, 0, time.UTC)
}

func TestBuildSignatureKnownGood(t *testing.T) {
	t.Parallel()

	// The expected value was computed by an independent HMAC implementation for
	// these fixed inputs, so this locks the exact string-to-hash byte layout —
	// method, content length, content type, the x-ms-date header, and the
	// /api/logs resource path. A defect in any of those is caught here, which a
	// test that re-ran the production construction could not detect.
	u := &legacyUploader{
		workspaceID: "ws-123",
		primaryKey:  base64.StdEncoding.EncodeToString([]byte("super-secret-key")),
	}
	const (
		date          = "Fri, 14 Aug 2026 12:34:56 GMT"
		contentLength = 42
		want          = "SharedKey ws-123:LaN0/spIvwQvZ7iq877OX7iEXAxiym9rTcRLiaoOZeU="
	)

	got, err := u.buildSignature(date, contentLength)
	if err != nil {
		t.Fatalf("buildSignature: %v", err)
	}
	if got != want {
		t.Errorf("buildSignature = %q, want %q", got, want)
	}
}

func TestLegacyUploaderUploadSuccess(t *testing.T) {
	t.Parallel()

	const workspaceID = "ws-123"
	primaryKey := base64.StdEncoding.EncodeToString([]byte("super-secret-key"))
	records := []record{{FalconEventID: "e1", Severity: "70"}}

	var gotAuth, gotDate, gotLogType, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		if req.URL.Path != "/api/logs" {
			t.Errorf("path = %s, want /api/logs", req.URL.Path)
		}
		if v := req.URL.Query().Get("api-version"); v != "2016-04-01" {
			t.Errorf("api-version = %s, want 2016-04-01", v)
		}
		gotAuth = req.Header.Get("Authorization")
		gotDate = req.Header.Get("x-ms-date")
		gotLogType = req.Header.Get("Log-Type")
		gotContentType = req.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	u := &legacyUploader{
		workspaceID: workspaceID,
		primaryKey:  primaryKey,
		baseURL:     srv.URL,
		httpClient:  srv.Client(),
		now:         fixedTime,
	}

	if err := u.upload(context.Background(), records); err != nil {
		t.Fatalf("upload: %v", err)
	}

	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotLogType != "FalconIntegrationGatewayLogs" {
		t.Errorf("Log-Type = %q, want FalconIntegrationGatewayLogs", gotLogType)
	}
	wantDate := fixedTime().Format(http.TimeFormat)
	if gotDate != wantDate {
		t.Errorf("x-ms-date = %q, want %q", gotDate, wantDate)
	}
	// The signature's exact byte layout is asserted by TestBuildSignatureKnownGood;
	// here we only confirm the header was set and scoped to the workspace.
	if !strings.HasPrefix(gotAuth, "SharedKey "+workspaceID+":") || gotAuth == "SharedKey "+workspaceID+":" {
		t.Errorf("Authorization = %q, want a non-empty SharedKey %s signature", gotAuth, workspaceID)
	}

	var sent []map[string]any
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("body not a JSON array of records: %v", err)
	}
	if len(sent) != 1 || sent[0]["FalconEventId"] != "e1" {
		t.Errorf("body = %v, want one record with FalconEventId=e1", sent)
	}
}

func TestLegacyUploaderNon2xxIsError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	u := &legacyUploader{
		workspaceID: "ws",
		primaryKey:  base64.StdEncoding.EncodeToString([]byte("k")),
		baseURL:     srv.URL,
		httpClient:  srv.Client(),
		now:         fixedTime,
	}

	if err := u.upload(context.Background(), []record{{FalconEventID: "x"}}); err == nil {
		t.Fatal("upload: want error on 500 response, got nil")
	}
}

func TestLegacyUploaderErrorIncludesResponseBody(t *testing.T) {
	t.Parallel()

	const body = `{"Error":"InvalidWorkspaceKey"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	u := &legacyUploader{
		workspaceID: "ws",
		primaryKey:  base64.StdEncoding.EncodeToString([]byte("k")),
		baseURL:     srv.URL,
		httpClient:  srv.Client(),
		now:         fixedTime,
	}

	err := u.upload(context.Background(), []record{{FalconEventID: "x"}})
	if err == nil {
		t.Fatal("upload: want error on 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidWorkspaceKey") {
		t.Errorf("error = %q, want it to include the Data Collector response body", err)
	}
}

func TestLegacyUploaderBadPrimaryKeyIsError(t *testing.T) {
	t.Parallel()

	u := &legacyUploader{
		workspaceID: "ws",
		primaryKey:  "not!!base64",
		baseURL:     "http://unused.invalid",
		httpClient:  http.DefaultClient,
		now:         fixedTime,
	}

	if err := u.upload(context.Background(), []record{{FalconEventID: "x"}}); err == nil {
		t.Fatal("upload: want error on undecodable primary key, got nil")
	}
}
