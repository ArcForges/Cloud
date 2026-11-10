// SPDX-License-Identifier: AGPL-3.0-only

// Package bridgeproof verifies the protected publisher's short-lived GitHub
// OIDC attestation for the schema-10 bridge. It never logs the JWT or secrets.
package bridgeproof

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	BridgeRevision      = "8e5f6e26aa97b123d9f60b91f780364a094e74cd"
	BridgeImageID       = "sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0"
	BridgeReleaseSHA256 = "d9c52a13c54b073758866c9e02168cc1e527cca92257df259e97298a5aa2a466"
	issuer              = "https://token.actions.githubusercontent.com"
	jwksURL             = issuer + "/.well-known/jwks"
	workflowRef         = "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main"
)

var (
	ErrUntrusted  = errors.New("the protected bridge promotion proof is invalid")
	hex40         = regexp.MustCompile(`^[a-f0-9]{40}$`)
	hex64         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	host          = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
	name          = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,62}$`)
	cloudAccount  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	cloudVersion  = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	registryImage = regexp.MustCompile(`^registry\.cloudflare\.com/[a-f0-9]{32}/arcforges-cloud@sha256:[a-f0-9]{64}$`)
)

// Context is non-secret evidence; the nonce is fresh for each preparation.
// PostgreSQL OIDs are re-read from the actual database inside the migration
// transaction. A single exact encoding is used as the GitHub OIDC audience.
type Context struct {
	Environment          string `json:"environment"`
	DatabaseHost         string `json:"databaseHost"`
	DatabasePort         uint16 `json:"databasePort"`
	DatabaseName         string `json:"databaseName"`
	DatabaseOID          uint32 `json:"databaseOid"`
	OwnerOID             uint32 `json:"ownerOid"`
	LegacyRole           string `json:"legacyRole"`
	LegacyRoleOID        uint32 `json:"legacyRoleOid"`
	BridgeRole           string `json:"bridgeRole"`
	BridgeRoleOID        uint32 `json:"bridgeRoleOid"`
	BridgeLogin          string `json:"bridgeLogin"`
	BridgeLoginOID       uint32 `json:"bridgeLoginOid"`
	Nonce                string `json:"nonce"`
	WorkflowRevision     string `json:"workflowRevision"`
	CloudAccount         string `json:"cloudAccount"`
	WorkerName           string `json:"workerName"`
	WorkerVersion        string `json:"workerVersion"`
	ContainerApplication string `json:"containerApplication"`
	RegistryImage        string `json:"registryImage"`
}

// Audience validates and hashes the exact context and immutable bridge identity.
func (c Context) Audience() (string, error) {
	if (c.Environment != "production" && c.Environment != "acceptance") ||
		!host.MatchString(c.DatabaseHost) || c.DatabasePort == 0 || !name.MatchString(c.DatabaseName) ||
		c.DatabaseOID == 0 || c.OwnerOID == 0 || !name.MatchString(c.LegacyRole) || c.LegacyRoleOID == 0 ||
		!name.MatchString(c.BridgeRole) || c.BridgeRoleOID == 0 || c.BridgeRole == c.LegacyRole ||
		!name.MatchString(c.BridgeLogin) || c.BridgeLoginOID == 0 || c.BridgeLogin == c.BridgeRole ||
		!hex64.MatchString(c.Nonce) || !hex40.MatchString(c.WorkflowRevision) ||
		!cloudAccount.MatchString(c.CloudAccount) || !name.MatchString(c.WorkerName) ||
		!cloudVersion.MatchString(c.WorkerVersion) || !cloudVersion.MatchString(c.ContainerApplication) ||
		!registryImage.MatchString(c.RegistryImage) ||
		c.RegistryImage != "registry.cloudflare.com/"+c.CloudAccount+"/arcforges-cloud@"+BridgeImageID {
		return "", ErrUntrusted
	}
	expectedWorker := "arcforges-cloud"
	if c.Environment == "acceptance" {
		expectedWorker = "arcforges-cloud-proof"
	}
	if c.WorkerName != expectedWorker {
		return "", ErrUntrusted
	}
	fields := []string{
		"ArcForges CTR06 protected promotion v1", c.Environment, c.DatabaseHost, strconv.Itoa(int(c.DatabasePort)),
		c.DatabaseName, strconv.FormatUint(uint64(c.DatabaseOID), 10), strconv.FormatUint(uint64(c.OwnerOID), 10),
		c.LegacyRole, strconv.FormatUint(uint64(c.LegacyRoleOID), 10), c.BridgeRole, strconv.FormatUint(uint64(c.BridgeRoleOID), 10),
		c.BridgeLogin, strconv.FormatUint(uint64(c.BridgeLoginOID), 10), c.Nonce, c.WorkflowRevision,
		BridgeRevision, BridgeImageID, BridgeReleaseSHA256, c.CloudAccount, c.WorkerName, c.WorkerVersion,
		c.ContainerApplication, c.RegistryImage,
	}
	digest := sha256.Sum256([]byte(strings.Join(fields, "\n")))
	return "urn:arcforges:ctr06:" + hex.EncodeToString(digest[:]), nil
}

type keySet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type tokenHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

type claims struct {
	Issuer      string          `json:"iss"`
	Subject     string          `json:"sub"`
	Audience    json.RawMessage `json:"aud"`
	Expires     int64           `json:"exp"`
	Issued      int64           `json:"iat"`
	NotBefore   int64           `json:"nbf"`
	Repository  string          `json:"repository"`
	Ref         string          `json:"ref"`
	SHA         string          `json:"sha"`
	Environment string          `json:"environment"`
	Event       string          `json:"event_name"`
	WorkflowRef string          `json:"workflow_ref"`
	WorkflowSHA string          `json:"workflow_sha"`
}

// Verified is constructed only after the issuer, signed claims, time and
// complete context have been checked. It deliberately retains no raw JWT.
type Verified struct {
	binding Context
	expires time.Time
	digest  string
	valid   bool
}

// ContextAt rechecks expiry after any database-lock wait. A zero or expired
// Verified cannot be supplied as proof of a promotion.
func (v *Verified) ContextAt(now time.Time) (Context, string, error) {
	if v == nil || !v.valid || !now.Before(v.expires) {
		return Context{}, "", ErrUntrusted
	}
	return v.binding, v.digest, nil
}

// VerifyGitHub uses only GitHub's fixed HTTPS JWKS endpoint. Network errors,
// redirects and unavailable keys refuse the migration; the JWT is not stored.
func VerifyGitHub(ctx context.Context, jwt string, binding Context, now time.Time) (*Verified, error) {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := verify(ctx, jwt, binding, now, client, jwksURL); err != nil {
		return nil, err
	}
	var c claims
	if err := decodePart(strings.Split(jwt, ".")[1], &c); err != nil {
		return nil, ErrUntrusted
	}
	digest, err := binding.PublicDigest()
	if err != nil {
		return nil, err
	}
	return &Verified{binding: binding, expires: time.Unix(c.Expires, 0), digest: digest, valid: true}, nil
}

func decodePart(part string, destination any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil || len(raw) > 16384 {
		return ErrUntrusted
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return ErrUntrusted
	}
	return nil
}

func verify(ctx context.Context, token string, binding Context, now time.Time, client *http.Client, keyURL string) error {
	audience, err := binding.Audience()
	if err != nil || len(token) > 32768 {
		return ErrUntrusted
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrUntrusted
	}
	var head tokenHeader
	var c claims
	if decodePart(parts[0], &head) != nil || decodePart(parts[1], &c) != nil ||
		head.Alg != "RS256" || head.Kid == "" || len(head.Kid) > 128 || len(head.Crit) != 0 ||
		(head.Typ != "" && head.Typ != "JWT") {
		return ErrUntrusted
	}
	var aud string
	if json.Unmarshal(c.Audience, &aud) != nil || aud != audience {
		return ErrUntrusted
	}
	nowUnix := now.Unix()
	event := "push"
	if binding.Environment == "acceptance" {
		event = "workflow_dispatch"
	}
	if c.Issuer != issuer || c.Subject != "repo:ArcForges/Cloud:environment:cloudflare" ||
		c.Repository != "ArcForges/Cloud" || c.Ref != "refs/heads/main" || c.Environment != "cloudflare" ||
		c.Event != event || c.WorkflowRef != workflowRef || c.WorkflowSHA != binding.WorkflowRevision ||
		c.SHA != binding.WorkflowRevision || c.Issued <= 0 || c.Issued > nowUnix+30 ||
		c.NotBefore > nowUnix+30 || c.Expires <= nowUnix || c.Expires <= c.Issued ||
		c.Expires-c.Issued > 600 {
		return ErrUntrusted
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return ErrUntrusted
	}
	response, err := client.Do(req)
	if err != nil {
		return ErrUntrusted
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrUntrusted
	}
	var keys keySet
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || json.Unmarshal(data, &keys) != nil || len(keys.Keys) > 64 {
		return ErrUntrusted
	}
	var key *rsa.PublicKey
	for _, k := range keys.Keys {
		if k.Kid != head.Kid || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if key != nil {
			return ErrUntrusted
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return ErrUntrusted
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return ErrUntrusted
		}
		key = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}
	}
	if key == nil {
		return ErrUntrusted
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrUntrusted
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return ErrUntrusted
	}
	return nil
}

// PublicDigest is safe to retain after verification; it contains no JWT.
func (c Context) PublicDigest() (string, error) {
	aud, err := c.Audience()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(aud, "urn:arcforges:ctr06:"), nil
}

func (c Context) String() string {
	digest, err := c.PublicDigest()
	if err != nil {
		return "invalid bridge proof context"
	}
	return fmt.Sprintf("bridge promotion context sha256=%s", digest)
}
