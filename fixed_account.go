package vault_plugin_secrets_grafana

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/Boostport/vault-plugin-secrets-grafana/client"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// A fixed service account belongs to one caller and one role. The plugin
// records each account it makes under accounts/<name>. It never uses an
// account that it did not make, so a hand-made account with the same name
// (perhaps with role Admin) cannot be taken over.

const accountsPrefix = "accounts/"

// Grafana accepts more, but a name from an identity template must not hold a
// slash (a storage path) or other surprises.
var accountName = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,190}$`)

type fixedAccount struct {
	ID     int64  `json:"id"`
	Vault  string `json:"vault_role"`
	Entity string `json:"entity_id"` // the OpenBao entity that owns the account
	URL    string `json:"grafana_url"`
}

// accountLock serialises creds reads with role writes and deletes.
var accountLock sync.Mutex // ponytail: one lock for the whole mount; reads are rare and fast

func (b *grafanaBackend) createFixedAccountToken(ctx context.Context, req *logical.Request, roleName string, role *grafanaRoleEntry) (*grafanaToken, *logical.Response, error) {
	if req.EntityID == "" {
		return nil, logical.ErrorResponse("service_account_template is set but the caller's token has no entity"), nil
	}
	name, err := framework.PopulateIdentityTemplate(role.ServiceAccountTemplate, req.EntityID, b.System())
	if err != nil {
		return nil, logical.ErrorResponse("service_account_template %q did not resolve for this caller: %s", role.ServiceAccountTemplate, err), nil
	}
	name = strings.ToLower(name)
	if !accountName.MatchString(name) {
		return nil, logical.ErrorResponse("service_account_template resolved to %q, which is not a valid account name", name), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, nil, err
	}

	// The caller (createUserCreds) holds accountLock.
	if len(role.RBACRoles) > 0 {
		return nil, logical.ErrorResponse("role %q has rbac_roles, which a fixed account cannot use", roleName), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil || config == nil {
		return nil, nil, fmt.Errorf("error reading config: %v", err)
	}
	sa, errResp, err := ensureFixedAccount(ctx, req.Storage, c, name, roleName, req.EntityID, config.URL, role)
	if errResp != nil || err != nil {
		return nil, errResp, err
	}

	tokenTTL := role.MaxTTL
	if tokenTTL == 0 {
		tokenTTL = role.TTL
	}
	if tokenTTL == 0 {
		tokenTTL = 24 * time.Hour
	}
	if max := b.System().MaxLeaseTTL(); max > 0 && tokenTTL > max {
		// OpenBao caps the lease at the mount maximum; the token must not outlive the lease.
		tokenTTL = max
	}
	token, err := c.CreateServiceAccountToken(client.CreateServiceAccountTokenInput{
		Name:             fmt.Sprintf("vault-%s", uuid.New()),
		ServiceAccountID: sa.ID,
		SecondsToLive:    int64(tokenTTL.Seconds()),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error creating service account token: %w", err)
	}
	if token.ID <= 0 {
		// A revoke with no token ID would delete the whole account.
		return nil, nil, fmt.Errorf("grafana returned token ID %d for service account %d; the token stays until it expires", token.ID, sa.ID)
	}

	return &grafanaToken{Token: token.Key, ServiceAccountID: sa.ID, TokenID: token.ID, TTL: tokenTTL}, nil, nil
}

// ensureFixedAccount returns the account for name. It makes the account when the
// plugin has no record of it, and sets the basic role of the Vault role each time.
func ensureFixedAccount(ctx context.Context, s logical.Storage, c *client.Grafana, name, roleName, entityID, grafanaURL string, role *grafanaRoleEntry) (*client.ServiceAccount, *logical.Response, error) {
	want := "None"
	if role.Role != "" {
		want = role.Role
	}

	var rec fixedAccount
	entry, err := s.Get(ctx, accountsPrefix+name)
	if err != nil {
		return nil, nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(&rec); err != nil {
			return nil, nil, err
		}
		if rec.Vault != roleName {
			return nil, logical.ErrorResponse("service account %q belongs to role %q; give each role its own service_account_template", name, rec.Vault), nil
		}
		if rec.URL != grafanaURL {
			return nil, logical.ErrorResponse("service account %q was made on %s, not on the current Grafana; use a new mount for another Grafana", name, rec.URL), nil
		}
		if rec.Entity != entityID {
			// For example a reused email: the new person must not get the old person's account.
			return nil, logical.ErrorResponse("service account %q belongs to another entity; an operator must delete accounts/%s and the account in Grafana", name, name), nil
		}
		sa, err := c.GetServiceAccount(rec.ID)
		switch {
		case client.IsNotFound(err):
			// Somebody deleted the account in Grafana: forget it and make a new one below.
			if err := s.Delete(ctx, accountsPrefix+name); err != nil {
				return nil, nil, err
			}
		case err != nil:
			return nil, nil, fmt.Errorf("error reading service account: %w", err)
		case sa.Name != name:
			return nil, logical.ErrorResponse("service account %d is now named %q, not %q; delete accounts/%s or rename it back", rec.ID, sa.Name, name, name), nil
		case sa.IsDisabled:
			// A Grafana admin disabled it to stop this caller. Do not undo that.
			return nil, logical.ErrorResponse("service account %q is disabled in Grafana", name), nil
		default:
			if sa.Role != want {
				if err := c.SetServiceAccountRole(sa.ID, want); err != nil {
					return nil, nil, err
				}
				sa.Role = want
			}
			return &sa, nil, nil
		}
	}

	existing, err := c.FindServiceAccount(name)
	if err != nil {
		return nil, nil, err
	}
	if existing != nil {
		return nil, logical.ErrorResponse("a service account named %q exists, but this plugin did not make it; rename or delete it in Grafana", name), nil
	}
	sa, err := c.CreateServiceAccount(client.CreateServiceAccountInput{Name: name, Role: want})
	if err != nil {
		return nil, nil, err
	}
	stored, err := logical.StorageEntryJSON(accountsPrefix+name, fixedAccount{ID: sa.ID, Vault: roleName, Entity: entityID, URL: grafanaURL})
	if err != nil {
		return nil, nil, err
	}
	if err := s.Put(ctx, stored); err != nil {
		if delErr := c.DeleteServiceAccount(sa.ID); delErr != nil {
			return nil, nil, fmt.Errorf("could not record service account %d (%q): %w; deleting it also failed, delete it in Grafana: %v", sa.ID, name, err, delErr)
		}
		return nil, nil, err
	}
	return &sa, nil, nil
}
