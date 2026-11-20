package vault_plugin_secrets_grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// Run against a real Grafana:
//
//	GRAFANA_TEST_URL=http://127.0.0.1:3999 GRAFANA_TEST_TOKEN=glsa_... go test -run TestFixedAccount -v
//
// The token needs the Admin role. The test leaves service accounts named
// agent-*@example.com in that Grafana.
func TestFixedAccount(t *testing.T) {
	url, adminToken := os.Getenv("GRAFANA_TEST_URL"), os.Getenv("GRAFANA_TEST_TOKEN")
	if url == "" || adminToken == "" {
		t.Skip("GRAFANA_TEST_URL and GRAFANA_TEST_TOKEN are not set")
	}
	ctx := context.Background()
	sys := &logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: 8 * time.Hour}
	b, err := Factory("test")(ctx, &logical.BackendConfig{System: sys})
	if err != nil {
		t.Fatal(err)
	}
	s := &logical.InmemStorage{}
	run := fmt.Sprint(time.Now().UnixNano())

	call := func(op logical.Operation, path string, data map[string]any, secret *logical.Secret) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: s, EntityID: "e", Secret: secret})
		if err != nil {
			t.Fatalf("%s %s: %v", op, path, err)
		}
		return resp
	}
	as := func(email string) {
		if email == "" {
			sys.EntityVal = &logical.Entity{ID: "e"}
			return
		}
		sys.EntityVal = &logical.Entity{ID: "e", Aliases: []*logical.Alias{{MountAccessor: "auth_oidc_x", Name: email}}}
	}
	creds := func(role string) (*logical.Response, string) {
		t.Helper()
		resp := call(logical.ReadOperation, "creds/"+role, nil, nil)
		if resp.IsError() {
			return resp, resp.Error().Error()
		}
		return resp, ""
	}
	mustCreds := func(role string) *logical.Response {
		t.Helper()
		resp, msg := creds(role)
		if msg != "" {
			t.Fatalf("creds/%s: %s", role, msg)
		}
		return resp
	}
	grafana := func(token, method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, url+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	account := func(id int64) map[string]any {
		t.Helper()
		code, sa := grafana(adminToken, "GET", fmt.Sprintf("/api/serviceaccounts/%d", id), "")
		if code != 200 {
			t.Fatalf("service account %d: HTTP %d", id, code)
		}
		return sa
	}
	saID := func(resp *logical.Response) int64 {
		id, _ := serviceAccountIDFromInternalData(resp.Secret.InternalData["service_account_id"])
		return id
	}
	works := func(token string) bool {
		code, _ := grafana(token, "GET", "/api/search?limit=1", "")
		return code == 200
	}

	call(logical.CreateOperation, "config", map[string]any{"type": GrafanaType, "url": url, "token": adminToken}, nil)
	if _, ok := call(logical.ReadOperation, "config", nil, nil).Data["token"]; ok {
		t.Fatal("config read returned the admin token")
	}
	tpl := "agent-{{identity.entity.aliases.auth_oidc_x.name}}"
	call(logical.CreateOperation, "roles/editor", map[string]any{"role": "Editor", "ttl": 3600, "max_ttl": 7200, "service_account_template": tpl}, nil)
	call(logical.CreateOperation, "roles/viewer", map[string]any{"role": "Viewer", "service_account_template": tpl}, nil)
	call(logical.CreateOperation, "roles/viewer2", map[string]any{"role": "Viewer", "service_account_template": "viewer-{{identity.entity.aliases.auth_oidc_x.name}}"}, nil)
	for _, bad := range []string{"{{identity.entity.name", "agent-shared"} {
		if resp := call(logical.CreateOperation, "roles/bad", map[string]any{"service_account_template": bad}, nil); !resp.IsError() {
			t.Fatalf("template %q was accepted", bad)
		}
	}

	alice := "alice-" + run + "@example.com"
	as(alice)
	first := mustCreds("editor")
	second := mustCreds("editor")
	if saID(first) != saID(second) {
		t.Fatal("two reads made two accounts")
	}
	sa := account(saID(first))
	if sa["name"] != "agent-"+alice || sa["role"] != "Editor" {
		t.Fatalf("account = %v %v", sa["name"], sa["role"])
	}
	t1, t2 := first.Data["token"].(string), second.Data["token"].(string)
	if !works(t1) || !works(t2) {
		t.Fatal("a new token does not work")
	}

	// Revoke deletes the token only.
	call(logical.RevokeOperation, "creds/editor", nil, first.Secret)
	if works(t1) || !works(t2) {
		t.Fatal("revoke deleted the wrong token")
	}
	account(saID(first))
	call(logical.RevokeOperation, "creds/editor", nil, first.Secret) // again: the token is gone already

	// A second role with the same template cannot take the account.
	if _, msg := creds("viewer"); !strings.Contains(msg, "belongs to role") {
		t.Fatalf("viewer with the editor account: %q", msg)
	}
	// A role with its own template gets its own account.
	if saID(mustCreds("viewer2")) == saID(first) {
		t.Fatal("viewer2 got the editor account")
	}

	// The role from the Vault role wins over a change in Grafana.
	grafana(adminToken, "PATCH", fmt.Sprintf("/api/serviceaccounts/%d", saID(first)), `{"role":"Admin"}`)
	mustCreds("editor")
	if account(saID(first))["role"] != "Editor" {
		t.Fatal("the role was not set back to Editor")
	}

	// A disabled account stays disabled.
	grafana(adminToken, "PATCH", fmt.Sprintf("/api/serviceaccounts/%d", saID(first)), `{"isDisabled":true}`)
	if _, msg := creds("editor"); !strings.Contains(msg, "disabled") {
		t.Fatalf("disabled account: %q", msg)
	}
	grafana(adminToken, "PATCH", fmt.Sprintf("/api/serviceaccounts/%d", saID(first)), `{"isDisabled":false}`)

	// An account deleted in Grafana is made again.
	grafana(adminToken, "DELETE", fmt.Sprintf("/api/serviceaccounts/%d", saID(first)), "")
	again := mustCreds("editor")
	if saID(again) == saID(first) || account(saID(again))["name"] != "agent-"+alice {
		t.Fatal("the deleted account was not made again")
	}

	// Another person gets another account.
	as("bob-" + run + "@example.com")
	if saID(mustCreds("editor")) == saID(again) {
		t.Fatal("bob got alice's account")
	}

	// An account that the plugin did not make is never used.
	mallory := "mallory-" + run + "@example.com"
	grafana(adminToken, "POST", "/api/serviceaccounts", `{"name":"agent-`+mallory+`","role":"Admin"}`)
	as(mallory)
	if _, msg := creds("editor"); !strings.Contains(msg, "did not make it") {
		t.Fatalf("hand-made account: %q", msg)
	}

	// No alias, or a name with a slash, gives no account.
	as("")
	if _, msg := creds("editor"); msg == "" {
		t.Fatal("a caller without the alias got a token")
	}
	as("a/b@example.com")
	if _, msg := creds("editor"); !strings.Contains(msg, "not a valid account name") {
		t.Fatalf("name with a slash: %q", msg)
	}

	// A role without a template keeps the upstream behaviour: a new account per lease, deleted on revoke.
	call(logical.CreateOperation, "roles/dynamic", map[string]any{"role": "Viewer"}, nil)
	dyn := mustCreds("dynamic")
	call(logical.RevokeOperation, "creds/dynamic", nil, dyn.Secret)
	if code, _ := grafana(adminToken, "GET", fmt.Sprintf("/api/serviceaccounts/%d", saID(dyn)), ""); code != 404 {
		t.Fatalf("dynamic account after revoke: HTTP %d", code)
	}
}
