// SPDX-License-Identifier: AGPL-3.0-only

package bridgeproof

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProtectedBridgeOIDCAuthenticatesTheEntireBinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
		"n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1}),
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()
	now := time.Unix(1800000000, 0)
	binding := Context{
		Environment: "production", DatabaseHost: "ep-test.example.neon.tech", DatabasePort: 5432,
		DatabaseName: "center", DatabaseOID: 123, OwnerOID: 124, LegacyRole: "center_runtime", LegacyRoleOID: 125,
		BridgeRole: "center_ctr06", BridgeRoleOID: 126, BridgeLogin: "center_ctr06_a", BridgeLoginOID: 127,
		Nonce: strings.Repeat("a", 64), WorkflowRevision: strings.Repeat("b", 40),
		CloudAccount: strings.Repeat("c", 32), WorkerName: "arcforges-cloud",
		WorkerVersion: "00000000-0000-4000-8000-000000000001", ContainerApplication: "00000000-0000-4000-8000-000000000002",
		RegistryImage: "registry.cloudflare.com/" + strings.Repeat("c", 32) + "/arcforges-cloud@" + BridgeImageID,
	}
	aud, err := binding.Audience()
	if err != nil {
		t.Fatal(err)
	}
	if aud != "urn:arcforges:ctr06:e0fc4ad2317891a32c7e8cecfbcb772ac26560afa5df7992d60df1cfed4aeedc" {
		t.Fatal("audience differs from the protected publisher fixture")
	}
	base := map[string]any{
		"iss": issuer, "sub": "repo:ArcForges/Cloud:environment:cloudflare", "aud": aud,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"repository": "ArcForges/Cloud", "ref": "refs/heads/main", "sha": binding.WorkflowRevision,
		"environment": "cloudflare", "event_name": "push", "workflow_ref": workflowRef,
		"workflow_sha": binding.WorkflowRevision,
	}
	sign := func(claims map[string]any, signingKey *rsa.PrivateKey) string {
		t.Helper()
		header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
		payload, _ := json.Marshal(claims)
		body := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return body + "." + b64(signature)
	}
	check := func(token string, c Context, at time.Time) error {
		return verify(context.Background(), token, c, at, server.Client(), server.URL)
	}
	token := sign(base, key)
	if err := check(token, binding, now); err != nil {
		t.Fatalf("authentic bound proof refused: %v", err)
	}
	for name, mutate := range map[string]func(*Context){
		"other database OID":     func(c *Context) { c.DatabaseOID++ },
		"other owner OID":        func(c *Context) { c.OwnerOID++ },
		"other endpoint":         func(c *Context) { c.DatabaseHost = "other.example" },
		"other legacy role":      func(c *Context) { c.LegacyRoleOID++ },
		"other bridge role":      func(c *Context) { c.BridgeRoleOID++ },
		"other bridge login":     func(c *Context) { c.BridgeLoginOID++ },
		"other nonce":            func(c *Context) { c.Nonce = strings.Repeat("e", 64) },
		"other workflow":         func(c *Context) { c.WorkflowRevision = strings.Repeat("f", 40) },
		"other provider version": func(c *Context) { c.WorkerVersion = "00000000-0000-4000-8000-000000000003" },
		"other application":      func(c *Context) { c.ContainerApplication = "00000000-0000-4000-8000-000000000004" },
		"other digest": func(c *Context) {
			c.RegistryImage = "registry.cloudflare.com/" + c.CloudAccount + "/arcforges-cloud@sha256:" + strings.Repeat("f", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			if check(token, changed, now) == nil {
				t.Fatal("changed context was trusted")
			}
		})
	}
	for name, change := range map[string]map[string]any{
		"wrong issuer":            {"iss": "https://example.invalid"},
		"wrong subject":           {"sub": "repo:Other/Cloud:environment:cloudflare"},
		"wrong repository":        {"repository": "Other/Cloud"},
		"wrong ref":               {"ref": "refs/heads/not-main"},
		"wrong environment":       {"environment": "other"},
		"wrong event":             {"event_name": "workflow_dispatch"},
		"wrong workflow":          {"workflow_ref": "ArcForges/Cloud/.github/workflows/other.yml@refs/heads/main"},
		"wrong workflow revision": {"workflow_sha": strings.Repeat("0", 40)},
		"wrong source revision":   {"sha": strings.Repeat("0", 40)},
		"wrong audience":          {"aud": "unbound"},
		"long expiry":             {"exp": now.Add(time.Hour).Unix()},
		"expired":                 {"exp": now.Add(-time.Second).Unix(), "iat": now.Add(-time.Minute).Unix()},
		"not yet valid":           {"nbf": now.Add(time.Minute).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			modified := make(map[string]any, len(base))
			for k, v := range base {
				modified[k] = v
			}
			for k, v := range change {
				modified[k] = v
			}
			if check(sign(modified, key), binding, now) == nil {
				t.Fatal("invalid signed claims were trusted")
			}
		})
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if check(sign(base, other), binding, now) == nil {
		t.Fatal("signature from a different key was trusted")
	}
	if check(token, binding, now.Add(6*time.Minute)) == nil {
		t.Fatal("expired proof was trusted")
	}
}
