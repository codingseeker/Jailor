package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Credential struct {
	Username      string
	Password      string
	IdentityToken string
}

const authFileEnv = "JAILOR_REGISTRY_AUTH"

func defaultAuthFile() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "jailor", "auth.json")
	}
	return ""
}

type authDoc struct {
	Registry map[string]struct {
		Username      string `json:"username,omitempty"`
		Password      string `json:"password,omitempty"`
		IdentityToken string `json:"identitytoken,omitempty"`
	} `json:"registry"`
}

func authFilePath() string {
	if p := os.Getenv(authFileEnv); p != "" {
		return p
	}
	return defaultAuthFile()
}

func loadAuthDoc() (authDoc, error) {
	var doc authDoc
	path := authFilePath()
	if path == "" {
		return doc, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return doc, nil
	}
	if err != nil {
		return doc, fmt.Errorf("registry: read auth file %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("registry: parse auth file %s: %w", path, err)
	}
	return doc, nil
}

func lookupCredentials(host string) (Credential, bool) {
	doc, err := loadAuthDoc()
	if err == nil {
		for h, c := range doc.Registry {
			if hostMatches(host, h) {
				return Credential{Username: c.Username, Password: c.Password, IdentityToken: c.IdentityToken}, true
			}
		}
	}

	if (host == DefaultHost || host == "docker.io" || host == "registry.hub.docker.com") &&
		os.Getenv("JAILOR_REGISTRY_USERNAME") != "" &&
		os.Getenv("JAILOR_REGISTRY_PASSWORD") != "" {
		return Credential{
			Username: os.Getenv("JAILOR_REGISTRY_USERNAME"),
			Password: os.Getenv("JAILOR_REGISTRY_PASSWORD"),
		}, true
	}
	return Credential{}, false
}

func hostMatches(requestHost, configured string) bool {
	if requestHost == configured {
		return true
	}
	if configured == "docker.io" || configured == "registry.hub.docker.com" {
		return requestHost == DefaultHost
	}
	return false
}

type challenge struct {
	Scheme  string
	Realm   string
	Service string
	Scope   string
}

func parseChallenge(value string) (challenge, bool) {
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 {
		return challenge{}, false
	}
	c := challenge{Scheme: parts[0]}
	for _, kv := range strings.Split(parts[1], ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch strings.ToLower(key) {
		case "realm":
			c.Realm = val
		case "service":
			c.Service = val
		case "scope":
			c.Scope = val
		}
	}
	if c.Scheme != "Bearer" && c.Scheme != "Basic" {
		return challenge{}, false
	}
	return c, true
}

type tokenBody struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

func (c *Client) bearerToken(host string, ch challenge, cred Credential) (string, error) {
	cacheKey := host + "|" + ch.Service + "|" + ch.Scope
	if v, ok := c.tokenCache.Load(cacheKey); ok {
		return v.(string), nil
	}
	if ch.Realm == "" {
		return "", errors.New("registry: bearer challenge has no realm")
	}

	u, err := url.Parse(ch.Realm)
	if err != nil {
		return "", fmt.Errorf("registry: invalid token realm %q: %w", ch.Realm, err)
	}
	q := u.Query()
	if ch.Service != "" {
		q.Set("service", ch.Service)
	}
	if ch.Scope != "" {
		q.Set("scope", ch.Scope)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "jailor")
	if cred.Username != "" && cred.Password != "" {
		req.SetBasicAuth(cred.Username, cred.Password)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized && cred.Username == "" {
			return "", ErrAuthRequired
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf("%w: token service for %s rejected the stored credentials", ErrAuthRequired, host)
		}
		return "", fmt.Errorf("registry: token service: %s", apiError(resp))
	}
	var tb tokenBody
	if err := json.NewDecoder(resp.Body).Decode(&tb); err != nil {
		return "", fmt.Errorf("registry: token service response: %w", err)
	}
	token := tb.Token
	if token == "" {
		token = tb.AccessToken
	}
	if token == "" {
		return "", errors.New("registry: token service returned no token")
	}
	c.tokenCache.Store(cacheKey, token)
	return token, nil
}

func (c *Client) credentials(host string) (Credential, bool) {
	if c.Creds != nil {
		crd := c.Creds(host)
		return crd, crd.Username != "" || crd.Password != "" || crd.IdentityToken != ""
	}
	return lookupCredentials(host)
}

func (c *Client) do(method, host, apiPath string, header http.Header, body func() io.Reader, scope string) (*http.Response, error) {
	cred, _ := c.credentials(host)
	var lastErr error
	for attempt := 0; attempt < c.retries(); attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
		}
		resp, err := c.authenticatedRequest(method, host, apiPath, header, body, cred, scope)
		if err != nil {

			if errors.Is(err, ErrAuthRequired) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if transient(resp.StatusCode) {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = fmt.Errorf("registry: transient %s", resp.Status)
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = ErrNotFound
	}
	return nil, lastErr
}

func (c *Client) authenticatedRequest(method, host, apiPath string, header http.Header, body func() io.Reader, cred Credential, scope string) (*http.Response, error) {
	reqBody := buildBody(body)
	req, err := http.NewRequest(method, c.apiURL(host, apiPath), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "jailor")
	copyHeaders(req.Header, header)
	if cred.Username != "" && cred.Password != "" {
		req.SetBasicAuth(cred.Username, cred.Password)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	challengeStr := resp.Header.Get("WWW-Authenticate")
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	ch, ok := parseChallenge(challengeStr)
	if !ok {
		return nil, ErrAuthRequired
	}

	if ch.Scheme == "Basic" {
		if cred.Username == "" || cred.Password == "" {
			return nil, ErrAuthRequired
		}
		req2, err := http.NewRequest(method, c.apiURL(host, apiPath), buildBody(body))
		if err != nil {
			return nil, err
		}
		req2.Header.Set("User-Agent", "jailor")
		copyHeaders(req2.Header, header)
		req2.SetBasicAuth(cred.Username, cred.Password)
		return c.HTTP.Do(req2)
	}

	tokenScope := ch.Scope
	if scope != "" {
		tokenScope = scope
	}
	ch2 := ch
	ch2.Scope = tokenScope
	token, err := c.bearerToken(host, ch2, cred)
	if err != nil {
		return nil, err
	}
	req3, err := http.NewRequest(method, c.apiURL(host, apiPath), buildBody(body))
	if err != nil {
		return nil, err
	}
	req3.Header.Set("User-Agent", "jailor")
	copyHeaders(req3.Header, header)
	req3.Header.Set("Authorization", "Bearer "+token)
	resp2, err := c.HTTP.Do(req3)
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode == http.StatusUnauthorized {
		return resp2, fmt.Errorf("%w: registry %s rejected the presented credentials", ErrAuthRequired, host)
	}
	return resp2, nil
}

func buildBody(build func() io.Reader) io.Reader {
	if build == nil {
		return nil
	}
	return build()
}

func copyHeaders(dst, src http.Header) {
	if src == nil {
		return
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
