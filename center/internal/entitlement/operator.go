// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The operator grant (AF-CTR-03 part B; decision n2, SEC-10, PLT-10): the interim way, until AF-OPS-01's operator service, for an
// operator to give an account named features for a bounded time. It exists on the official hosted center only and needs a catalogue.
// A grant is made by a HUMAN account session of an operator (a live identity.operator row, or the bootstrap owner), with step-up
// evidence for the center-defined operation center.operatorGrant whose target is the SHA-256 of the canonical request, consumed in
// the grant's own transaction; it writes, in that one transaction with a command receipt and an audit event, one compensation service
// term and one AdminGrant capability grant per named feature, all ending at the request's expiry. A refusal is audited in its own
// transaction. The logic is here, behind injected dependencies, so AF-OPS-01's OperatorService can call it as the page does.

// The step-up operation class and the audit events of the operator grant.
const (
	// OperatorGrantClass is the center-defined step-up operation of the operator grant (the contract has no row for it): its target
	// object is the request itself, named by the SHA-256 of its canonical text.
	OperatorGrantClass = "center.operatorGrant"
	// AuditOperatorGrantIssued and AuditOperatorGrantRefused are the audit events (plan section (j)).
	AuditOperatorGrantIssued  = "entitlement.operator_grant.issued"
	AuditOperatorGrantRefused = "entitlement.operator_grant.refused"
	// OperatorOperation is the command receipt's operation name.
	OperatorOperation = "center.operatorGrant"
)

// Why operator grants are not available at all.
var (
	ErrGrantsSelfHosted  = errors.New("operator grants exist only on the official hosted center")
	ErrGrantsNoCatalogue = errors.New("operator grants need a valid plan catalogue")
)

// OperatorPolicy is what operator grants may do under the center's configuration.
type OperatorPolicy struct {
	// MaxExpiry is the longest expiry from now: 90 days in a production configuration, 400 otherwise.
	MaxExpiry time.Duration
	// AllowCatalogueWide is false in a production configuration: a grant of every key of the catalogue is refused there.
	AllowCatalogueWide bool
	// Keys are the capability keys of the catalogue, the only features a grant may name.
	Keys []string
}

// OperatorRequest is a request for an operator grant, as the operator states it.
type OperatorRequest struct {
	// Account is the account to give the features to (uuid text).
	Account string
	// Features are the capability keys to grant; All names every key of the catalogue (a catalogue-wide grant).
	Features []string
	All      bool
	// Reason is the operator's recorded cause, 1 to 512 characters without a control character.
	Reason string
	// ExpiresAt is when the grant ends: required, in the future, at most MaxExpiry from now.
	ExpiresAt Micros
	// SourceRef is the ticket or incident (an opaque reference of at most 96 characters); it makes the request idempotent.
	SourceRef string
	// SelfApproval is the mandatory justification of a grant to the operator's own account.
	SelfApproval string
}

// MaxSourceRef bounds an operator grant's source reference: the grants' own references are <reference>:<feature> within 128.
const MaxSourceRef = 96

// canonicalRequest is the document the step-up target hash covers; its field order is fixed and its strings are JSON-escaped, so
// two requests that differ in any field, in any byte of the reason included, have different hashes.
type canonicalRequest struct {
	Version      int      `json:"v"`
	Operation    string   `json:"operation"`
	Operator     string   `json:"operator"`
	Account      string   `json:"account"`
	Features     []string `json:"features"`
	All          bool     `json:"all"`
	Reason       string   `json:"reason"`
	ExpiresAt    int64    `json:"expiresAt"`
	SourceRef    string   `json:"sourceRef"`
	SelfApproval string   `json:"selfApproval"`
}

// Canonical is the canonical text of a normalized request made by an operator.
func (r OperatorRequest) Canonical(operator platform.ID) []byte {
	features := slices.Clone(r.Features)
	slices.Sort(features)
	data, err := json.Marshal(canonicalRequest{Version: 1, Operation: OperatorOperation, Operator: operator.String(), Account: r.Account, Features: features, All: r.All,
		Reason: r.Reason, ExpiresAt: int64(r.ExpiresAt), SourceRef: r.SourceRef, SelfApproval: r.SelfApproval})
	if err != nil {
		panic(err) // a struct of strings, numbers and a bool always encodes
	}
	return data
}

// TargetHash is the step-up target of the request: the SHA-256 of its canonical text (SEC-10).
func (r OperatorRequest) TargetHash(operator platform.ID) [32]byte {
	return sha256.Sum256(r.Canonical(operator))
}

// TargetHashHex is TargetHash as the lowercase hexadecimal text a step-up challenge names.
func (r OperatorRequest) TargetHashHex(operator platform.ID) string {
	hash := r.TargetHash(operator)
	return hex.EncodeToString(hash[:])
}

// OperatorCaller is the authenticated caller of an operator grant: a HUMAN account session.
type OperatorCaller struct {
	UserID platform.ID
	// Scope is the session's scope: only account is a person's session (a mobile.limited session upgrades first).
	Scope string
}

// Operator issues operator grants.
type Operator struct {
	db      *store.DB
	service *Service
	policy  func() (OperatorPolicy, error)
	clock   func() time.Time
}

// NewOperator is the operator grant service. The policy comes from the plan configuration (feature.Configuration.OperatorGrants);
// it is read for every call, and an error from it refuses the call.
func NewOperator(db *store.DB, service *Service, policy func() (OperatorPolicy, error), clock func() time.Time) *Operator {
	if clock == nil {
		clock = time.Now
	}
	return &Operator{db: db, service: service, policy: policy, clock: clock}
}

// Policy is the policy the operator grants run under now, or the reason they are refused (ErrGrantsSelfHosted, ErrGrantsNoCatalogue):
// the keys that may be granted, the longest expiry and whether a catalogue-wide grant is allowed. The operations page shows it.
func (o *Operator) Policy() (OperatorPolicy, error) { return o.policy() }

// IsOperator reports whether an account is an operator now: a live operator row, or the owner who bootstrapped this center.
func IsOperator(ctx context.Context, tx pgx.Tx, user platform.ID, now time.Time) (bool, error) {
	var operator bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identity.operator WHERE user_id = $1 AND revoked_at IS NULL AND granted_at <= $2 AND expires_at > $2)
    OR EXISTS (SELECT 1 FROM identity.bootstrap WHERE user_id = $1)`, user, now).Scan(&operator)
	return operator, store.Sanitize("read the operator role", err)
}

// CanOperate answers IsOperator in a transaction of its own (the operations page's visibility check).
func (o *Operator) CanOperate(ctx context.Context, user platform.ID) (bool, error) {
	var operator bool
	err := o.db.InTx(ctx, "read the operator role", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) (err error) {
		operator, err = IsOperator(ctx, tx, user, o.clock())
		return err
	})
	return operator, err
}

// Review checks a request the way a grant does, without any effect, and returns it normalized (features sorted and unique, All
// resolved, the combined reason of a self-grant checked) with the policy it was checked under. The page shows the result and the
// target hash to the operator before the step-up.
func (o *Operator) Review(ctx context.Context, caller OperatorCaller, request OperatorRequest) (OperatorRequest, error) {
	normalized, _, err := o.check(ctx, caller, request)
	return normalized, err
}

// reasonCodes are the closed audit reasons of a refused operator grant.
func reasonOf(refusal *arc.Refusal) string {
	switch {
	case refusal.Code == "permission_denied":
		return "not_operator"
	case refusal.Code == "step_up_required":
		return "step_up_required"
	case refusal.Code == "invalid_argument":
		return "invalid_argument"
	case refusal.Code == "not_found":
		return "account_not_found"
	case refusal.Code == "already_exists":
		return "already_granted"
	case refusal.Code == "invalid_state":
		if refusal.Reason != "" {
			return refusal.Reason
		}
		return "invalid_state"
	}
	return "refused"
}

// check validates a request against the policy and the caller, reading the store only for the operator role and the target account.
func (o *Operator) check(ctx context.Context, caller OperatorCaller, request OperatorRequest) (OperatorRequest, OperatorPolicy, error) {
	policy, err := o.policy()
	switch {
	case errors.Is(err, ErrGrantsSelfHosted):
		return OperatorRequest{}, OperatorPolicy{}, arc.InvalidState("operator_grant", "self_hosted")
	case err != nil:
		return OperatorRequest{}, OperatorPolicy{}, arc.InvalidState("operator_grant", "no_catalogue")
	}
	if caller.Scope != "account" || caller.UserID == (platform.ID{}) {
		return OperatorRequest{}, OperatorPolicy{}, arc.PermissionDenied(OperatorOperation)
	}
	now := o.clock()
	var operator bool
	if err = o.db.InTx(ctx, "read the operator role", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) (err error) {
		operator, err = IsOperator(ctx, tx, caller.UserID, now)
		return err
	}); err != nil {
		return OperatorRequest{}, OperatorPolicy{}, err
	}
	if !operator {
		return OperatorRequest{}, OperatorPolicy{}, arc.PermissionDenied(OperatorOperation)
	}
	normalized, refusal := Normalize(request, policy, caller.UserID, FromTime(now))
	if refusal != nil {
		return OperatorRequest{}, OperatorPolicy{}, refusal
	}
	return normalized, policy, nil
}

// Normalize applies the bounds of an operator grant request to a request under a policy: the account is a canonical uuid, the
// features are keys of the catalogue (sorted, unique, not empty), a catalogue-wide grant is refused where the policy refuses it, the
// reason and the source reference are bounded, the expiry lies in the future and within the policy, and a grant to the operator's own
// account carries its self-approval justification (and the reason and justification fit one stored reason). It performs no read.
func Normalize(request OperatorRequest, policy OperatorPolicy, operator platform.ID, now Micros) (OperatorRequest, *arc.Refusal) {
	if correlation.IDBytes(request.Account) == nil {
		return OperatorRequest{}, arc.InvalidArgument("account", "format")
	}
	features := request.Features
	if request.All {
		features = policy.Keys
	}
	if len(features) == 0 {
		return OperatorRequest{}, arc.InvalidArgument("features", "required")
	}
	unique := slices.Clone(features)
	slices.Sort(unique)
	unique = slices.Compact(unique)
	if len(unique) != len(features) {
		return OperatorRequest{}, arc.InvalidArgument("features", "repeated")
	}
	for _, key := range unique {
		if !slices.Contains(policy.Keys, key) {
			return OperatorRequest{}, arc.InvalidArgument("features", "not_in_catalogue")
		}
	}
	wide := len(unique) == len(policy.Keys)
	if wide && !policy.AllowCatalogueWide {
		return OperatorRequest{}, arc.InvalidState("operator_grant", "catalogue_wide")
	}
	if !IsReason(request.Reason) {
		return OperatorRequest{}, arc.InvalidArgument("reason", "length_or_characters")
	}
	if request.SourceRef == "" || len(request.SourceRef) > MaxSourceRef || !IsOpaqueReference(request.SourceRef) {
		return OperatorRequest{}, arc.InvalidArgument("source_ref", "format")
	}
	if request.ExpiresAt <= now {
		return OperatorRequest{}, arc.InvalidArgument("expires_at", "not_in_the_future")
	}
	if int64(request.ExpiresAt)-int64(now) > policy.MaxExpiry.Microseconds() {
		return OperatorRequest{}, arc.InvalidArgument("expires_at", "too_far")
	}
	self := request.Account == operator.String()
	switch {
	case self && request.SelfApproval == "":
		return OperatorRequest{}, arc.InvalidState("operator_grant", "self_approval_required")
	case self && !IsReason(request.SelfApproval):
		return OperatorRequest{}, arc.InvalidArgument("self_approval", "length_or_characters")
	case !self && request.SelfApproval != "":
		return OperatorRequest{}, arc.InvalidArgument("self_approval", "only_for_a_self_grant")
	case self && utf16Length(request.Reason)+len(selfApprovalSeparator)+utf16Length(request.SelfApproval) > 512:
		return OperatorRequest{}, arc.InvalidArgument("reason", "too_long_with_the_self_approval")
	}
	request.Features, request.All = unique, wide
	return request, nil
}

const selfApprovalSeparator = " | self-approval: "

// storedReason is the reason the grants record: the operator's, and for a self-grant its justification as well.
func (r OperatorRequest) storedReason() string {
	if r.SelfApproval == "" {
		return r.Reason
	}
	return r.Reason + selfApprovalSeparator + r.SelfApproval
}

// GrantCall is one operator grant.
type GrantCall struct {
	Caller  OperatorCaller
	Request OperatorRequest
	// CommandID is the client's idempotency key: the same command with the same request answers its first result.
	CommandID platform.ID
	// Consume consumes, in the grant's transaction, the caller's step-up evidence for OperatorGrantClass whose target hash is the
	// given one (identity.ConsumeEvidenceFor); it returns arc.StepUpRequired when there is none.
	Consume func(ctx context.Context, tx pgx.Tx, target [32]byte, now time.Time) error
	// Correlation is the call's correlation identity, recorded in the audit events.
	Correlation *platform.ID
}

// GrantResult is what a grant wrote.
type GrantResult struct {
	TermID    string   `json:"termId"`
	GrantIDs  []string `json:"grantIds"`
	Features  []string `json:"features"`
	ExpiresAt int64    `json:"expiresAt"`
	Version   int64    `json:"version"`
	// Replayed is true when the command had already been executed and this is its stored result.
	Replayed bool `json:"-"`
}

var errRevisionConflict = errors.New("the account changed under the grant")

// Grant issues an operator grant, or returns the refusal (an *arc.Refusal), which it has audited in a transaction of its own. A
// store failure is returned as it is; a grant whose COMMIT went unanswered is store.ErrCommitUnknown.
func (o *Operator) Grant(ctx context.Context, call GrantCall) (GrantResult, error) {
	request, _, err := o.check(ctx, call.Caller, call.Request)
	if err != nil {
		return GrantResult{}, o.refused(ctx, call, err)
	}
	canonical := request.Canonical(call.Caller.UserID)
	target := sha256.Sum256(canonical)
	for range attempts {
		var result GrantResult
		outcome, err := platform.Execute(ctx, o.db, platform.Command{Principal: "account:" + call.Caller.UserID.String(), CommandID: call.CommandID,
			Operation: OperatorOperation, Request: canonical}, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
			var written GrantResult
			var err error
			if written, err = o.write(ctx, tx, call, request, target); err != nil {
				return nil, err
			}
			result = written
			return json.Marshal(written)
		})
		switch {
		case errors.Is(err, errRevisionConflict):
			continue
		case errors.Is(err, platform.ErrCommandIDReused):
			return GrantResult{}, o.refused(ctx, call, arc.CommandIDReused())
		case errors.Is(err, platform.ErrCommandInProgress):
			return GrantResult{}, &store.Error{Operation: "grant features", Kind: store.ErrContention}
		case err != nil:
			var refusal *arc.Refusal
			if errors.As(err, &refusal) {
				return GrantResult{}, o.refused(ctx, call, refusal)
			}
			return GrantResult{}, err
		}
		if outcome.Replayed {
			if err = json.Unmarshal(outcome.Result, &result); err != nil {
				return GrantResult{}, err
			}
			result.Replayed = true
		}
		return result, nil
	}
	// The account changed under every attempt: nothing was written, and the same command may be sent again.
	return GrantResult{}, &store.Error{Operation: "grant features", Kind: store.ErrContention}
}

// write is the grant's effect, in the caller's transaction.
func (o *Operator) write(ctx context.Context, tx pgx.Tx, call GrantCall, request OperatorRequest, target [32]byte) (GrantResult, error) {
	now := o.clock()
	// The role is read again under the grant's own transaction: a revocation that committed since the check is honoured.
	operator, err := IsOperator(ctx, tx, call.Caller.UserID, now)
	if err != nil {
		return GrantResult{}, err
	}
	if !operator {
		return GrantResult{}, arc.PermissionDenied(OperatorOperation)
	}
	// The evidence is consumed first of the effects, and the whole transaction rolls back with it when anything below refuses.
	if err = call.Consume(ctx, tx, target, now); err != nil {
		return GrantResult{}, err
	}
	var accountState int16
	account, _ := parseAccount(request.Account)
	if err = tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1", account).Scan(&accountState); errors.Is(err, pgx.ErrNoRows) {
		return GrantResult{}, arc.NotFound("account", account[:])
	} else if err != nil {
		return GrantResult{}, store.Sanitize("read the target account", err)
	}
	if accountState != 1 && accountState != 2 {
		return GrantResult{}, arc.InvalidState("operator_grant", "account_state")
	}
	// The account's fence row is locked first, so the load below is the history no other writer can change before this commit.
	var revision int64
	if err = tx.QueryRow(ctx, "SELECT rev FROM entitlement.revision WHERE account_id = $1 FOR UPDATE", account).Scan(&revision); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return GrantResult{}, store.Sanitize("lock the entitlement revision", err)
	}
	state, err := Load(ctx, tx, request.Account)
	if err != nil {
		return GrantResult{}, err
	}
	definitions := o.service.definitions.Current()
	at, err := WriteInstant(state, now)
	if err != nil {
		return GrantResult{}, arc.InvalidState("operator_grant", "clock")
	}
	expires := request.ExpiresAt
	if expires <= at {
		return GrantResult{}, arc.InvalidArgument("expires_at", "not_in_the_future")
	}
	actor := "operator:" + call.Caller.UserID.String()
	reason := request.storedReason()
	term := ServiceTermFact{TermID: o.service.ids.NewID(), Kind: TermCompensation, StartsAt: at, EndsAt: expires, AuthorizedAt: at, CreatedAt: at}
	add := Append{Terms: []TermRow{{Fact: term, PeriodRef: request.SourceRef}}}
	records, activations := withActivation(state.Records, definitions, at)
	add.Activations = activations
	records.Terms = append(append([]ServiceTermFact(nil), records.Terms...), term)
	var grantIDs []string
	for _, key := range request.Features {
		sourceRef := request.SourceRef + ":" + key
		for _, existing := range state.Records.Grants {
			if existing.Source == SourceAdminGrant && equalStrings(existing.SourceRef, &sourceRef) {
				return GrantResult{}, arc.AlreadyExists("grant", nil)
			}
		}
		grant := Grant{GrantID: o.service.ids.NewID(), AccountID: request.Account, Kind: KindCapability, Subject: key, Value: CapabilityValue{}, Source: SourceAdminGrant,
			SourceRef: &sourceRef, EffectiveFrom: at, EffectiveUntil: &expires, IssuedByActor: actor, CreatedAt: at, Reason: &reason}
		if refusal := ValidateIssue(IssueGrantRequest{AccountID: request.Account, Kind: grant.Kind, Subject: key, Value: grant.Value, Source: grant.Source, SourceRef: grant.SourceRef,
			EffectiveFrom: at, EffectiveUntil: &expires, IssuedByActor: actor, Reason: &reason}); refusal != "" {
			return GrantResult{}, arc.InvalidArgument("features", "not_admitted")
		}
		records.Grants = append(records.Grants, grant)
		add.Grants = append(add.Grants, grant)
		grantIDs = append(grantIDs, grant.GrantID)
	}
	snapshot, err := seal(state, records, definitions, at)
	if err != nil {
		return GrantResult{}, arc.InvalidState("operator_grant", "history")
	}
	outcome, err := Commit(ctx, tx, request.Account, state.Revision, add, snapshot, now)
	if err != nil {
		var stored *store.Error
		if errors.As(err, &stored) && stored.SQLState == "23505" && (stored.Constraint == "service_term_period" || stored.Constraint == "grant_source_ref_once") {
			return GrantResult{}, arc.AlreadyExists("grant", nil)
		}
		return GrantResult{}, err
	}
	if outcome == RevisionConflict {
		return GrantResult{}, errRevisionConflict
	}
	result := GrantResult{TermID: term.TermID, GrantIDs: grantIDs, Features: request.Features, ExpiresAt: int64(expires), Version: snapshot.Version}
	payload, err := json.Marshal(map[string]any{"account": request.Account, "features": request.Features, "expiresAt": int64(expires), "term": term.TermID, "grants": grantIDs,
		"self": request.SelfApproval != "", "catalogueWide": request.All, "sourceRef": request.SourceRef, "version": snapshot.Version,
		"reasonLength": utf16Length(request.Reason), "reasonSha256": digestOf(request.Reason)})
	if err != nil {
		return GrantResult{}, err
	}
	// The audit is the last statement before the commit: a failed append refuses the grant.
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "account:" + call.Caller.UserID.String(), EventType: AuditOperatorGrantIssued,
		CorrelationID: call.Correlation, CommandID: &call.CommandID, TargetKind: "account", TargetID: request.Account, Payload: payload})
	if err != nil {
		return GrantResult{}, err
	}
	return result, nil
}

func digestOf(text string) string {
	digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digest[:])
}

func parseAccount(text string) (platform.ID, bool) {
	var id platform.ID
	raw := correlation.IDBytes(text)
	if len(raw) != len(id) {
		return id, false
	}
	copy(id[:], raw)
	return id, true
}

// refused audits a refusal in a transaction of its own (it is no effect of the refused grant) and returns the refusal; when the
// audit itself fails the store error is returned instead, so a refusal is never silent.
func (o *Operator) refused(ctx context.Context, call GrantCall, err error) error {
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) {
		return err
	}
	payload := map[string]any{"reason": reasonOf(refusal), "code": refusal.Key()}
	if call.Request.Account != "" && correlation.IDBytes(call.Request.Account) != nil {
		payload["account"] = call.Request.Account
	}
	if len(call.Request.Features) > 0 && len(call.Request.Features) <= maxAuditFeatures {
		payload["features"] = call.Request.Features
	}
	data, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return marshalErr
	}
	targetID := call.Caller.UserID.String()
	target := "account"
	auditErr := o.db.InTx(ctx, "audit an operator grant refusal", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: o.clock(), ActorRef: "account:" + targetID, EventType: AuditOperatorGrantRefused,
			Reason: reasonOf(refusal), CorrelationID: call.Correlation, TargetKind: target, TargetID: targetID, Payload: data})
		return err
	})
	if auditErr != nil {
		return auditErr
	}
	return refusal
}

// maxAuditFeatures bounds the feature list an audit payload repeats (the six gated keys).
const maxAuditFeatures = 6
