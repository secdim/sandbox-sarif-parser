package game

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Client wraps HTTP calls to the SecDim game API.
type Client struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewClient initializes a new game API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// doRequest constructs and executes an HTTP request to game API endpoints.
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	base := strings.TrimRight(c.baseURL, "/")
	url := fmt.Sprintf("%s/%s", base, endpoint)
	var req *http.Request
	var err error
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
	}
	// Set the API key header
	req.Header.Set("Authorization", fmt.Sprintf("Api-Key %s", c.apiKey))
	return c.client.Do(req)
}

func (c *Client) Get(ctx context.Context, slug string) (*Game, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "game/"+slug, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var g Game
		if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
			return nil, err
		}
		return &g, nil
	case http.StatusForbidden:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET game: unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func (c *Client) Create(ctx context.Context, payload *CreateGamePayload) (*Game, error) {
	// Validate mandatory fields before sending request
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "game/", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var g Game
		if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
			return nil, err
		}
		return &g, nil

	case http.StatusForbidden:
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Patch game: unexpected status %d: %s", resp.StatusCode, string(body))
		return nil, ErrUnauthorized

	case http.StatusBadRequest:
		return nil, ErrAlreadyExists

	default:
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Create game: unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func (c *Client) Patch(ctx context.Context, patch *GamePatch) (*Game, error) {
	resp, err := c.doRequest(ctx, http.MethodPatch, "game/", patch)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var updated Game
		if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
			return nil, err
		}
		return &updated, nil
	case http.StatusForbidden:
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Patch game: unexpected status %d: %s", resp.StatusCode, string(body))
		return nil, ErrUnauthorized
	default:
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Patch game: unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func (c *Client) Ensure(ctx context.Context, g *Game) (*Game, error) {
	existing, err := c.Get(ctx, g.Slug)
	if err == nil {
		return existing, nil
	}
	if errors.Is(err, ErrUnauthorized) {
		return nil, ErrUnauthorized
	}
	if errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return nil, err
}
