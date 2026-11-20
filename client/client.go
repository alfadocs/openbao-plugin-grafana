package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

type Grafana struct {
	client      *http.Client
	bearerToken string
	baseURL     url.URL
}

func New(baseURL, bearerToken string) (*Grafana, error) {

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing base URL: %w", err)
	}

	return &Grafana{
		client:      &http.Client{},
		bearerToken: bearerToken,
		baseURL:     *u,
	}, nil
}

func (g *Grafana) do(method, requestPath string, query url.Values, body []byte, responseStruct any) error {
	requestURL := g.baseURL
	requestURL.Path = path.Join(requestURL.Path, requestPath)
	requestURL.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewBuffer(body))

	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", g.bearerToken))
	req.Header.Add("Content-Type", "application/json")

	resp, err := g.client.Do(req)

	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}

	defer resp.Body.Close()

	bodyContents, err := io.ReadAll(resp.Body)

	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode > 299 {
		return &StatusError{Code: resp.StatusCode, Body: string(bodyContents)}
	}

	if responseStruct == nil {
		return nil
	}

	err = json.Unmarshal(bodyContents, responseStruct)
	if err != nil {
		return fmt.Errorf("error decoding json response: %w", err)
	}

	return nil
}

// StatusError is a response from Grafana with a status code above 299.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("error response from server (%d): %s", e.Code, e.Body)
}

// IsNotFound reports whether err is a 404 response from Grafana.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}
