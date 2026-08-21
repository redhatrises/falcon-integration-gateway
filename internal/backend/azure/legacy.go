package azure

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// legacyLogType is the Log-Type header value (the custom log table name) the
// Data Collector API records events under.
const legacyLogType = "FalconIntegrationGatewayLogs"

// legacyAPIVersion is the Data Collector API version query parameter.
const legacyAPIVersion = "2016-04-01"

// legacyUploader posts records to the Azure Monitor HTTP Data Collector API,
// authenticating each request with a shared-key HMAC-SHA256 signature.
//
// now is injected so the request date (which is part of the signed string) is
// deterministic under test; baseURL is injected for the same reason. The
// primary key is a secret and is never logged.
type legacyUploader struct {
	workspaceID string
	primaryKey  string
	baseURL     string
	httpClient  *http.Client
	now         func() time.Time
}

// buildSignature returns the Authorization header value for a Data Collector
// POST of contentLength bytes sent with the given RFC 1123 date.
func (u *legacyUploader) buildSignature(date string, contentLength int) (string, error) {
	stringToHash := "POST\n" + strconv.Itoa(contentLength) + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"
	key, err := base64.StdEncoding.DecodeString(u.primaryKey)
	if err != nil {
		return "", fmt.Errorf("azure: decode primary key: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToHash))
	encoded := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("SharedKey %s:%s", u.workspaceID, encoded), nil
}

// upload marshals records to a JSON array and posts them to the Data Collector
// API. A non-2xx response is returned as an error so the worker can retry.
func (u *legacyUploader) upload(ctx context.Context, records []record) error {
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("azure: marshal records: %w", err)
	}

	date := u.now().UTC().Format(http.TimeFormat)
	sig, err := u.buildSignature(date, len(body))
	if err != nil {
		return err
	}

	url := u.baseURL + "/api/logs?api-version=" + legacyAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("azure: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", sig)
	req.Header.Set("Log-Type", legacyLogType)
	req.Header.Set("x-ms-date", date)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("azure: post to data collector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The Data Collector API reports the reason (bad signature, disabled
		// workspace, quota) in the body; surface a bounded slice of it so the
		// operator is not left guessing from a bare status code.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("azure: data collector returned status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
