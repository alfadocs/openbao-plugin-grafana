package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type CreateServiceAccountInput struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	IsDisabled *bool  `json:"isDisabled,omitempty"`
}

type CreateServiceAccountTokenInput struct {
	Name             string `json:"name"`
	ServiceAccountID int64  `json:"-"`
	SecondsToLive    int64  `json:"secondsToLive,omitempty"`
}

type ServiceAccount struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Login      string     `json:"login"`
	OrgID      int64      `json:"orgId"`
	IsDisabled bool       `json:"isDisabled"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  *time.Time `json:"updatedAt"`
	AvatarURL  string     `json:"avatarUrl"`
	Role       string     `json:"role"`
	Teams      []string   `json:"teams"`
}

type ServiceAccountToken struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

func (g *Grafana) CreateServiceAccount(input CreateServiceAccountInput) (ServiceAccount, error) {
	result := ServiceAccount{}

	data, err := json.Marshal(input)
	if err != nil {
		return result, fmt.Errorf("error marshalling input: %w", err)
	}

	err = g.do(http.MethodPost, "/api/serviceaccounts", nil, data, &result)

	if err != nil {
		return result, fmt.Errorf("error creating service account: %w", err)
	}

	return result, nil
}

func (g *Grafana) DeleteServiceAccount(serviceAccountID int64) error {
	err := g.do(http.MethodDelete, fmt.Sprintf("/api/serviceaccounts/%d", serviceAccountID), nil, nil, nil)

	if err != nil {
		return fmt.Errorf("error deleting service account: %w", err)
	}

	return nil
}

func (g *Grafana) CreateServiceAccountToken(input CreateServiceAccountTokenInput) (ServiceAccountToken, error) {

	result := ServiceAccountToken{}

	data, err := json.Marshal(input)
	if err != nil {
		return result, fmt.Errorf("error marshalling input: %w", err)
	}

	err = g.do(http.MethodPost, fmt.Sprintf("/api/serviceaccounts/%d/tokens", input.ServiceAccountID), nil, data, &result)

	if err != nil {
		return result, fmt.Errorf("error creating service account token: %w", err)
	}

	return result, nil
}

// GetServiceAccount returns the service account with the ID. The error is a
// StatusError with code 404 when it does not exist.
func (g *Grafana) GetServiceAccount(serviceAccountID int64) (ServiceAccount, error) {
	result := ServiceAccount{}
	err := g.do(http.MethodGet, fmt.Sprintf("/api/serviceaccounts/%d", serviceAccountID), nil, nil, &result)
	return result, err
}

// FindServiceAccount returns the service account with exactly this name, or nil.
func (g *Grafana) FindServiceAccount(name string) (*ServiceAccount, error) {
	var result struct {
		ServiceAccounts []ServiceAccount `json:"serviceAccounts"`
	}
	// The search matches parts of names, so filter for the exact name.
	query := url.Values{"query": {name}, "perpage": {"1000"}}
	if err := g.do(http.MethodGet, "/api/serviceaccounts/search", query, nil, &result); err != nil {
		return nil, fmt.Errorf("error searching service accounts: %w", err)
	}
	for _, sa := range result.ServiceAccounts {
		if sa.Name == name {
			return &sa, nil
		}
	}
	return nil, nil
}

// SetServiceAccountRole sets the basic role (Viewer, Editor, Admin or None).
func (g *Grafana) SetServiceAccountRole(serviceAccountID int64, role string) error {
	data, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return err
	}
	if err := g.do(http.MethodPatch, fmt.Sprintf("/api/serviceaccounts/%d", serviceAccountID), nil, data, nil); err != nil {
		return fmt.Errorf("error setting service account role: %w", err)
	}
	return nil
}

// DeleteServiceAccountToken deletes one token. A token that is already gone is not an error.
func (g *Grafana) DeleteServiceAccountToken(serviceAccountID, tokenID int64) error {
	err := g.do(http.MethodDelete, fmt.Sprintf("/api/serviceaccounts/%d/tokens/%d", serviceAccountID, tokenID), nil, nil, nil)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("error deleting service account token: %w", err)
	}
	return nil
}
