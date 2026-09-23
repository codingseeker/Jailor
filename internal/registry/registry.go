package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"jailor/internal/image"
)

const DefaultHost = "registry-1.docker.io"

const DefaultMaxConcurrent = 4

const defaultRetries = 3

type Client struct {
	HTTP *http.Client

	Insecure bool

	MaxConcurrent int

	Retries int

	Creds func(host string) Credential

	tokenCache sync.Map
}

func New() *Client {
	return &Client{
		HTTP:          &http.Client{Timeout: 5 * time.Minute},
		MaxConcurrent: DefaultMaxConcurrent,
		Retries:       defaultRetries,
	}
}

func (c *Client) maxConcurrent() int {
	if c.MaxConcurrent > 0 {
		return c.MaxConcurrent
	}
	return DefaultMaxConcurrent
}

func (c *Client) retries() int {
	if c.Retries > 0 {
		return c.Retries
	}
	return defaultRetries
}

var ErrAuthRequired = errors.New("registry: authentication required")

var ErrNotFound = errors.New("registry: not found")

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

func apiError(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("%w: empty response", ErrNotFound)
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	var doc struct {
		Errors []Error `json:"errors"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		return fmt.Errorf("registry: %s", resp.Status)
	}
	if err := json.Unmarshal(body, &doc); err == nil && len(doc.Errors) > 0 {
		e := doc.Errors[0]
		if e.Message != "" {
			return fmt.Errorf("registry: %s (%s)", e.Message, e.Code)
		}
		return fmt.Errorf("registry: %s", e.Code)
	}
	return fmt.Errorf("registry: %s: %s", resp.Status, trimmed)
}

func Resolve(refStr string) (image.Ref, error) {
	r, err := image.ParseRef(refStr)
	if err != nil {
		return image.Ref{}, err
	}
	if r.Registry == "" && !r.Digest.Valid() {
		r.Registry = DefaultHost
		if !strings.Contains(r.Name, "/") {
			r.Name = "library/" + r.Name
		}
	}
	if r.Tag == "" && !r.Digest.Valid() {
		r.Tag = "latest"
	}
	return r, nil
}

func (c *Client) scheme(host string) string {
	if c.Insecure {
		return "http"
	}
	if host == "localhost" || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "[::1]") {
		return "http"
	}
	return "https"
}

func (c *Client) apiURL(host, path string) string {
	return c.scheme(host) + "://" + host + path
}

func transient(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func httpOK(resp *http.Response, want int) error {
	if resp == nil {
		return ErrNotFound
	}
	if resp.StatusCode == want {
		return nil
	}
	return apiError(resp)
}
