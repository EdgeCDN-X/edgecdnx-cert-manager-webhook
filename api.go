package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiClient struct {
	baseURL string
	key     string
	http    *http.Client
}

type apiMetadata struct {
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion"`
}

type apiZone struct {
	Metadata apiMetadata `json:"metadata"`
	Spec     struct {
		Zone string `json:"zone"`
	} `json:"spec"`
}

type recordSpec struct {
	DNSName       string   `json:"dnsName"`
	RecordType    string   `json:"recordType"`
	RecordTTL     int      `json:"recordTTL"`
	RoutingPolicy string   `json:"routingPolicy"`
	Targets       []string `json:"targets"`
}

type apiRecord struct {
	Metadata apiMetadata `json:"metadata"`
	Spec     recordSpec  `json:"spec"`
}

type apiError struct {
	method string
	status int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("EdgeCDN-X API %s returned HTTP %d", e.method, e.status)
}

func hasStatus(err error, status int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.status == status
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
	return &apiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		key:     key,
		http: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (a *apiClient) request(ctx context.Context, method, path string, payload, result interface{}) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode API request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create API request: %w", err)
	}
	req.Header.Set("Authorization", "ApiKey "+a.key)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("call EdgeCDN-X API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not include response bodies: proxies or servers may echo credentials.
		return &apiError{method: method, status: resp.StatusCode}
	}
	if result != nil {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil {
			return fmt.Errorf("read API response: %w", err)
		}
		if len(data) > 1<<20 {
			return errors.New("API response exceeds 1 MiB")
		}
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("decode API response: %w", err)
		}
	}
	return nil
}
