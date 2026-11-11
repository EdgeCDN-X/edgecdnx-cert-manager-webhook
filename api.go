package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	edgecdnx "github.com/EdgeCDN-X/edgecdnx-sdk-go"
	"k8s.io/klog/v2"
)

type apiClient struct {
	*edgecdnx.Client
	key  string
	http *http.Client
}

func hasStatus(err error, status int) bool {
	var apiErr *edgecdnx.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == status
}

func newAPIClient(baseURL, key string) (*apiClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("EDGECDNX_API_URL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, " \t\r\n") {
		return nil, errors.New("EDGECDNX_API_KEY must contain an API key")
	}
	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &apiTransport{base: http.DefaultTransport, key: key},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client, err := edgecdnx.NewClient(baseURL,
		edgecdnx.WithAPIKey(key), edgecdnx.WithHTTPClient(httpClient),
		edgecdnx.WithUserAgent("edgecdnx-cert-manager-webhook"),
	)
	if err != nil {
		return nil, err
	}
	return &apiClient{Client: client, key: key, http: httpClient}, nil
}

// Keep server bodies out of returned errors: a proxy may echo credentials.
func (a *apiClient) safeError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr *edgecdnx.APIError
	if errors.As(err, &apiErr) {
		return &edgecdnx.APIError{
			StatusCode: apiErr.StatusCode,
			Message:    fmt.Sprintf("EdgeCDN-X API returned HTTP %d", apiErr.StatusCode),
		}
	}
	return &redactedError{err: err, key: a.key}
}

type redactedError struct {
	err error
	key string
}

func (e *redactedError) Error() string { return strings.ReplaceAll(e.err.Error(), e.key, "[REDACTED]") }
func (e *redactedError) Unwrap() error { return e.err }

// The SDK owns requests and decoding; the transport preserves bounded responses
// and redacted debug logging without ever logging Authorization headers.
type apiTransport struct {
	base http.RoundTripper
	key  string
}

func (t *apiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	debug := klog.V(4)
	redact := func(s string) string { return strings.ReplaceAll(s, t.key, "[REDACTED]") }
	if debug.Enabled() {
		var body []byte
		if req.GetBody != nil {
			reader, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("read API request for logging: %w", err)
			}
			body, err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				return nil, fmt.Errorf("read API request for logging: %w", err)
			}
		}
		debug.InfoS("EdgeCDN-X API request", "method", req.Method, "url", req.URL.String(), "body", redact(string(body)))
	}
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		if debug.Enabled() {
			debug.InfoS("EdgeCDN-X API request failed", "method", req.Method, "url", req.URL.String(),
				"duration", time.Since(start), "error", redact(err.Error()))
		}
		return nil, err
	}
	limit := int64(1 << 20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limit = 4 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read API response: %w", err)
	}
	if debug.Enabled() {
		debug.InfoS("EdgeCDN-X API response", "method", req.Method, "url", req.URL.String(),
			"status", resp.StatusCode, "duration", time.Since(start), "body", redact(string(body)))
	}
	if int64(len(body)) > limit {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil, errors.New("API response exceeds 1 MiB")
		}
		body = body[:limit]
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func (t *apiTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
