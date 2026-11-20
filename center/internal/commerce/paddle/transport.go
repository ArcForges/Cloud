// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxProviderBody = 1 << 20
	pageSize        = 20
	maxPages        = 8
)

// Config binds the API key to one Paddle realm and enables only explicitly
// approved checkout and portal origins. Transport is the optional HTTP peer
// used by isolated integration tests. Requests always name the pinned origin.
type Config struct {
	Environment     Environment
	APIKey          string
	CheckoutOrigins []string
	PortalOrigins   []string
	Transport       http.RoundTripper
}

type Client struct {
	origin    string
	apiKey    string
	http      *http.Client
	checkouts map[string]bool
	portals   map[string]bool
}

// NewClient selects the fixed v1 HTTPS origin without making a request.
// https://developer.paddle.com/api-reference/about/
func NewClient(cfg Config) (*Client, error) {
	origin := cfg.Environment.origin()
	prefix := "pdl_live_apikey_"
	if cfg.Environment == Sandbox {
		prefix = "pdl_sdbx_apikey_"
	}
	if origin == "" || !validSecret(cfg.APIKey) || !strings.HasPrefix(cfg.APIKey, prefix) || len(cfg.APIKey) == len(prefix) {
		return nil, ErrConfiguration
	}
	checkouts, ok := allowedOrigins(cfg.CheckoutOrigins)
	if !ok {
		return nil, ErrConfiguration
	}
	portals, ok := allowedOrigins(cfg.PortalOrigins)
	if !ok {
		return nil, ErrConfiguration
	}
	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: strings.TrimPrefix(origin, "https://"),
			},
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			ExpectContinueTimeout:  time.Second,
			IdleConnTimeout:        time.Minute,
			MaxResponseHeaderBytes: 64 << 10,
			MaxConnsPerHost:        16,
			MaxIdleConns:           16,
			MaxIdleConnsPerHost:    8,
			ForceAttemptHTTP2:      true,
		}
	}
	return &Client{origin: origin, apiKey: cfg.APIKey, checkouts: checkouts, portals: portals, http: &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

type envelope struct {
	Data json.RawMessage `json:"data"`
	Err  *struct {
		Type string `json:"type"`
		Code string `json:"code"`
	} `json:"error"`
	Meta struct {
		RequestID  string `json:"request_id"`
		Pagination *struct {
			HasMore *bool  `json:"has_more"`
			Next    string `json:"next"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (c *Client) request(ctx context.Context, operation, method, path string, query url.Values, input any, output any) (envelope, error) {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return envelope{}, ErrInvalidRequest
		}
		body = bytes.NewReader(raw)
	}
	endpoint := c.origin + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return envelope{}, ErrInvalidRequest
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
		// Do not hand the transport a replayable checkout or mutation.
		req.GetBody = nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Paddle-Version", Version)
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	response, err := c.http.Do(req)
	if err != nil {
		kind := "request_failed"
		if errors.Is(err, context.DeadlineExceeded) {
			kind = "deadline"
		} else if errors.Is(err, context.Canceled) {
			kind = "cancelled"
		}
		return envelope{}, &Error{Operation: operation, Transport: kind, cause: ErrUncertain}
	}
	defer response.Body.Close()

	failure := &Error{Operation: operation, Status: response.StatusCode, cause: ErrUncertain}
	if supplied := response.Header.Get("Content-Type"); supplied != "" {
		media, _, err := mime.ParseMediaType(supplied)
		if err != nil || media != "application/json" {
			return envelope{}, failure
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxProviderBody+1))
	if err != nil || len(raw) > maxProviderBody {
		failure.Transport = "response_read"
		return envelope{}, failure
	}
	var reply envelope
	if decodeJSON(raw, &reply) != nil {
		return envelope{}, failure
	}
	if safeDiagnostic(reply.Meta.RequestID) {
		failure.RequestID = reply.Meta.RequestID
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if reply.Err != nil && safeDiagnostic(reply.Err.Code) &&
			(reply.Err.Type == "request_error" || reply.Err.Type == "api_error") {
			failure.Code = reply.Err.Code
			switch response.StatusCode {
			case 400, 401, 403, 404, 405, 422, 429:
				failure.cause = ErrRefused
			}
		}
		return envelope{}, failure
	}
	if reply.Err != nil || len(reply.Data) == 0 || bytes.Equal(reply.Data, []byte("null")) || json.Unmarshal(reply.Data, output) != nil {
		return envelope{}, failure
	}
	return reply, nil
}

func safeDiagnostic(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func allowedOrigins(raw []string) (map[string]bool, bool) {
	if len(raw) == 0 || len(raw) > 16 {
		return nil, false
	}
	result := make(map[string]bool, len(raw))
	for _, value := range raw {
		u, ok := httpsURL(value)
		if !ok || u.Path != "" || u.RawQuery != "" || u.ForceQuery || value != originOf(u) || result[value] {
			return nil, false
		}
		result[value] = true
	}
	return result, true
}

func httpsURL(raw string) (*url.URL, bool) {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "#\\ \r\n\t") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		strings.HasSuffix(u.Hostname(), ".") || strings.HasSuffix(u.Host, ":") {
		return nil, false
	}
	return u, true
}

func originOf(u *url.URL) string { return u.Scheme + "://" + strings.ToLower(u.Host) }

// Follow only the cursor of a provider next link on the same fixed authority
// and path. The caller reconstructs the request from the established filters.
func (c *Client) nextCursor(reply envelope, path, idPrefix string) (string, error) {
	page := reply.Meta.Pagination
	if page == nil || page.HasMore == nil {
		return "", ErrUncertain
	}
	if !*page.HasMore {
		return "", nil
	}
	u, ok := httpsURL(page.Next)
	if !ok || originOf(u) != c.origin || u.Path != path || u.RawPath != "" {
		return "", ErrUncertain
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["after"]) != 1 || !providerID(q.Get("after"), idPrefix) {
		return "", ErrUncertain
	}
	return q.Get("after"), nil
}

func list[T any](ctx context.Context, c *Client, operation, path, prefix string, query url.Values) ([]T, error) {
	query.Set("per_page", "20")
	var result []T
	seen := make(map[string]bool)
	for range maxPages {
		var batch []T
		reply, err := c.request(ctx, operation, http.MethodGet, path, query, nil, &batch)
		if err != nil {
			return nil, err
		}
		if batch == nil || len(batch) > pageSize {
			return nil, &Error{Operation: operation, cause: ErrUncertain}
		}
		result = append(result, batch...)
		after, err := c.nextCursor(reply, path, prefix)
		if err != nil || seen[after] {
			return nil, &Error{Operation: operation, cause: ErrUncertain}
		}
		if after == "" {
			return result, nil
		}
		if len(batch) == 0 {
			return nil, &Error{Operation: operation, cause: ErrUncertain}
		}
		seen[after] = true
		query.Set("after", after)
	}
	return nil, &Error{Operation: operation, cause: ErrUncertain}
}
