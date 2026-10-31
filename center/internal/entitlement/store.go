// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// ErrStoreDefect is a stored value or a store answer that is not what the schema promises (an unknown enumeration, a payload that does
// not read back as its kind). It is a defect or a deployment skew, never a guess: nothing is interpreted and the call fails closed.
var ErrStoreDefect = errors.New("the entitlement store holds a value it does not understand")

// StoredSnapshot is the stored form of a snapshot (entitlement.snapshot): the version, the instants, the definitions version and the
// resolver's canonical text, which decides equality.
type StoredSnapshot struct {
	AccountID          string
	Version            int64
	ComputedAt         Micros
	ValidUntil         *Micros
	DefinitionsVersion string
	// Content is the canonical text of the snapshot's content (Content.Canonical).
	Content string
}

// Stored is the stored form of a resolved snapshot.
func (s Snapshot) Stored() StoredSnapshot {
	return StoredSnapshot{AccountID: s.AccountID, Version: s.Version, ComputedAt: s.ComputedAt, ValidUntil: s.Content.ValidUntil,
		DefinitionsVersion: s.Content.DefinitionsVersion, Content: s.Content.Canonical()}
}

// SameEffectAs compares two stored snapshots by their canonical text.
func (s StoredSnapshot) SameEffectAs(other StoredSnapshot) bool { return s.Content == other.Content }

// SameAs is full equality, the one a rebuild must satisfy.
func (s StoredSnapshot) SameAs(other StoredSnapshot) bool {
	return s.AccountID == other.AccountID && s.Version == other.Version && s.ComputedAt == other.ComputedAt && equalMicros(s.ValidUntil, other.ValidUntil) &&
		s.DefinitionsVersion == other.DefinitionsVersion && s.Content == other.Content
}

// CapabilityEntry is one capability entry of a snapshot.
type CapabilityEntry struct {
	Key     string
	Granted bool
	Reason  Reason
}

// Capability reads one capability entry from the canonical text; false when the snapshot has no entry for the key (a key the
// definitions of its version do not define), or the line does not read back (a defect, reported as no entry so a gate fails closed).
func (s StoredSnapshot) Capability(key string) (CapabilityEntry, bool) {
	prefix := "cap=" + key + "|"
	for line := range strings.SplitSeq(s.Content, "\n") {
		rest, found := strings.CutPrefix(line, prefix)
		if !found {
			continue
		}
		parts := strings.SplitN(rest, "|", 3)
		if len(parts) != 3 || (parts[0] != "0" && parts[0] != "1") {
			return CapabilityEntry{}, false
		}
		reason, ok := ParseReason(parts[1])
		if !ok {
			return CapabilityEntry{}, false
		}
		return CapabilityEntry{Key: key, Granted: parts[0] == "1", Reason: reason}, true
	}
	return CapabilityEntry{}, false
}

// State is what one account holds in the Entitlement store: every record, the stored snapshot, and the revision of the account's
// write fence.
type State struct {
	Records  RecordSet
	Snapshot *StoredSnapshot
	// Revision advances on every commit of the account, including one that does not change the snapshot version. A commit that names a
	// stale revision is refused, so two writers never derive a snapshot from a history the other has already changed.
	Revision int64
}

// TermRow is a service term as its owner admission appends it: the interval the resolver reads with the columns the row keeps.
type TermRow struct {
	Fact            ServiceTermFact
	SubscriptionRef *string
	PeriodRef       string
}

// Append is the records to add in one commit. The store only ever appends: no row is updated or deleted. Term actions, status facts
// and feature releases have no runtime writer yet (their owners are later tasks), so they have no append here.
type Append struct {
	Grants      []Grant
	Revocations []Revocation
	Activations []DefinitionsActivation
	Terms       []TermRow
}

// CommitOutcome is the answer of a commit that reached the store.
type CommitOutcome int

// The outcomes.
const (
	// Committed: the records and the snapshot are stored.
	Committed CommitOutcome = iota + 1
	// RevisionConflict: the account changed since the caller loaded it; nothing was written.
	RevisionConflict
)

// loadLimit stops the read of any one kind of record one past the replay bound, so a history is never read without limit; the
// resolver refuses a history over the bound.
const loadLimit = MaxRecords + 1

// Load reads the whole state of an account within the caller's transaction. The caller opens it read-only at REPEATABLE READ so that
// every query sees one consistent history (the C# store gets the same from reading the revision before and after its pages).
func Load(ctx context.Context, tx pgx.Tx, account string) (State, error) {
	state := State{Records: EmptyRecords(account)}
	err := tx.QueryRow(ctx, "SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", account).Scan(&state.Revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return State{}, store.Sanitize("read the entitlement revision", err)
	}
	var snapshot StoredSnapshot
	var computed time.Time
	var valid *time.Time
	err = tx.QueryRow(ctx, "SELECT entitlement_version, computed_at, valid_until, definitions_version, content FROM entitlement.snapshot WHERE account_id = $1::uuid",
		account).Scan(&snapshot.Version, &computed, &valid, &snapshot.DefinitionsVersion, &snapshot.Content)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return State{}, store.Sanitize("read the entitlement snapshot", err)
	default:
		snapshot.AccountID, snapshot.ComputedAt, snapshot.ValidUntil = account, FromTime(computed), optionalMicros(valid)
		state.Snapshot = &snapshot
	}
	if state.Records.Grants, err = loadGrants(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.Revocations, err = loadRevocations(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.Terms, err = loadTerms(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.TermActions, err = loadTermActions(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.StatusFacts, err = loadStatusFacts(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.Activations, err = loadActivations(ctx, tx, account); err != nil {
		return State{}, err
	}
	if state.Records.FeatureReleases, err = loadReleases(ctx, tx); err != nil {
		return State{}, err
	}
	return state, nil
}

func optionalMicros(value *time.Time) *Micros {
	if value == nil {
		return nil
	}
	converted := FromTime(*value)
	return &converted
}

func optionalTime(value *Micros) *time.Time {
	if value == nil {
		return nil
	}
	converted := value.Time()
	return &converted
}

func defect(what string) error { return fmt.Errorf("%w: %s", ErrStoreDefect, what) }

// The numbers the schema stores for the enumerations: the 1-based position in the listed order.
func kindFromStored(value int16) (GrantKind, bool) {
	kind := GrantKind(value - 1)
	return kind, kind.Defined()
}

func sourceFromStored(value int16) (GrantSource, bool) {
	source := GrantSource(value - 1)
	return source, source.Defined()
}

func loadGrants(ctx context.Context, tx pgx.Tx, account string) ([]Grant, error) {
	rows, err := tx.Query(ctx, `SELECT grant_id::text, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at, reason
FROM entitlement.grant WHERE account_id = $1::uuid ORDER BY created_at, grant_id LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement grants", err)
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var grant Grant
		var kind, source int16
		var value []byte
		var from, created time.Time
		var until *time.Time
		if err = rows.Scan(&grant.GrantID, &kind, &grant.Subject, &value, &source, &grant.SourceRef, &from, &until, &grant.IssuedByActor, &created, &grant.Reason); err != nil {
			return nil, store.Sanitize("read the entitlement grants", err)
		}
		var ok bool
		if grant.Kind, ok = kindFromStored(kind); !ok {
			return nil, defect("a grant of an unknown kind")
		}
		if grant.Source, ok = sourceFromStored(source); !ok {
			return nil, defect("a grant of an unknown source")
		}
		if grant.Value, err = decodeValue(grant.Kind, value); err != nil {
			return nil, err
		}
		grant.AccountID, grant.EffectiveFrom, grant.EffectiveUntil, grant.CreatedAt = account, FromTime(from), optionalMicros(until), FromTime(created)
		grants = append(grants, grant)
	}
	return grants, store.Sanitize("read the entitlement grants", rows.Err())
}

func decodeValue(kind GrantKind, data []byte) (GrantValue, error) {
	var payload struct {
		Limit           *int64  `json:"limit"`
		Priority        *int64  `json:"priority"`
		CapacityPlanRef *string `json:"capacityPlanRef"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, defect("a grant payload that does not read back")
	}
	switch kind {
	case KindCapability:
		if payload.Limit != nil || payload.Priority != nil || payload.CapacityPlanRef != nil {
			return nil, defect("a capability payload with fields")
		}
		return CapabilityValue{}, nil
	case KindQuota:
		if payload.Limit == nil || payload.Priority == nil || payload.CapacityPlanRef != nil {
			return nil, defect("a quota payload that is incomplete")
		}
		return QuotaValue{Limit: *payload.Limit, Priority: *payload.Priority}, nil
	case KindAllowance:
		if payload.CapacityPlanRef == nil || payload.Priority == nil || payload.Limit != nil {
			return nil, defect("an allowance payload that is incomplete")
		}
		return AllowanceValue{CapacityPlanRef: *payload.CapacityPlanRef, Priority: *payload.Priority}, nil
	}
	return nil, defect("a payload of an unknown kind")
}

func encodeValue(value GrantValue) ([]byte, error) {
	switch typed := value.(type) {
	case CapabilityValue:
		return []byte("{}"), nil
	case QuotaValue:
		return json.Marshal(map[string]int64{"limit": typed.Limit, "priority": typed.Priority})
	case AllowanceValue:
		return json.Marshal(map[string]any{"capacityPlanRef": typed.CapacityPlanRef, "priority": typed.Priority})
	}
	return nil, errors.New("a grant value of an unknown type")
}

func loadRevocations(ctx context.Context, tx pgx.Tx, account string) ([]Revocation, error) {
	rows, err := tx.Query(ctx, `SELECT revocation_id::text, grant_id::text, reason_code, effective_from, issued_by_actor, created_at
FROM entitlement.revocation WHERE account_id = $1::uuid ORDER BY created_at, revocation_id LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement revocations", err)
	}
	defer rows.Close()
	var revocations []Revocation
	for rows.Next() {
		var revocation Revocation
		var from, created time.Time
		if err = rows.Scan(&revocation.RevocationID, &revocation.GrantID, &revocation.ReasonCode, &from, &revocation.IssuedByActor, &created); err != nil {
			return nil, store.Sanitize("read the entitlement revocations", err)
		}
		revocation.EffectiveFrom, revocation.CreatedAt = FromTime(from), FromTime(created)
		revocations = append(revocations, revocation)
	}
	return revocations, store.Sanitize("read the entitlement revocations", rows.Err())
}

func loadTerms(ctx context.Context, tx pgx.Tx, account string) ([]ServiceTermFact, error) {
	rows, err := tx.Query(ctx, `SELECT term_id::text, kind, starts_at, ends_at, grace_ends_at, authorized_at, created_at
FROM entitlement.service_term WHERE account_id = $1::uuid ORDER BY starts_at, term_id LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement service terms", err)
	}
	defer rows.Close()
	var terms []ServiceTermFact
	for rows.Next() {
		var term ServiceTermFact
		var kind int16
		var starts, ends, authorized, created time.Time
		var grace *time.Time
		if err = rows.Scan(&term.TermID, &kind, &starts, &ends, &grace, &authorized, &created); err != nil {
			return nil, store.Sanitize("read the entitlement service terms", err)
		}
		term.Kind = ServiceTermKind(kind - 1)
		if !term.Kind.Defined() {
			return nil, defect("a service term of an unknown kind")
		}
		term.StartsAt, term.EndsAt, term.GraceEndsAt, term.AuthorizedAt, term.CreatedAt = FromTime(starts), FromTime(ends), optionalMicros(grace), FromTime(authorized), FromTime(created)
		terms = append(terms, term)
	}
	return terms, store.Sanitize("read the entitlement service terms", rows.Err())
}

func loadTermActions(ctx context.Context, tx pgx.Tx, account string) ([]TermActionFact, error) {
	rows, err := tx.Query(ctx, `SELECT term_id::text, kind, effective_at, recorded_at FROM entitlement.service_term_action
WHERE account_id = $1::uuid ORDER BY recorded_at, action_id LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement term actions", err)
	}
	defer rows.Close()
	var actions []TermActionFact
	for rows.Next() {
		var action TermActionFact
		var kind int16
		var effective, recorded time.Time
		if err = rows.Scan(&action.TermID, &kind, &effective, &recorded); err != nil {
			return nil, store.Sanitize("read the entitlement term actions", err)
		}
		action.Kind = TermActionKind(kind - 1)
		if !action.Kind.Defined() {
			return nil, defect("a term action of an unknown kind")
		}
		action.EffectiveAt, action.RecordedAt = FromTime(effective), FromTime(recorded)
		actions = append(actions, action)
	}
	return actions, store.Sanitize("read the entitlement term actions", rows.Err())
}

func loadStatusFacts(ctx context.Context, tx pgx.Tx, account string) ([]StatusFact, error) {
	rows, err := tx.Query(ctx, `SELECT recorded_at, status, auto_renew, purchase_pending FROM entitlement.account_status_fact
WHERE account_id = $1::uuid ORDER BY recorded_at, status_fact_id LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement status facts", err)
	}
	defer rows.Close()
	var facts []StatusFact
	for rows.Next() {
		var fact StatusFact
		var status int16
		var recorded time.Time
		if err = rows.Scan(&recorded, &status, &fact.AutoRenew, &fact.PurchasePending); err != nil {
			return nil, store.Sanitize("read the entitlement status facts", err)
		}
		fact.Status = AccountStatus(status - 1)
		if !fact.Status.Defined() {
			return nil, defect("a status fact of an unknown status")
		}
		fact.RecordedAt = FromTime(recorded)
		facts = append(facts, fact)
	}
	return facts, store.Sanitize("read the entitlement status facts", rows.Err())
}

func loadActivations(ctx context.Context, tx pgx.Tx, account string) ([]DefinitionsActivation, error) {
	rows, err := tx.Query(ctx, `SELECT activated_at, definitions_version FROM entitlement.definitions_activation
WHERE account_id = $1::uuid ORDER BY activated_at LIMIT $2`, account, loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement definitions activations", err)
	}
	defer rows.Close()
	var activations []DefinitionsActivation
	for rows.Next() {
		var activation DefinitionsActivation
		var at time.Time
		if err = rows.Scan(&at, &activation.Version); err != nil {
			return nil, store.Sanitize("read the entitlement definitions activations", err)
		}
		activation.ActivatedAt = FromTime(at)
		activations = append(activations, activation)
	}
	return activations, store.Sanitize("read the entitlement definitions activations", rows.Err())
}

func loadReleases(ctx context.Context, tx pgx.Tx) ([]FeatureReleaseFact, error) {
	rows, err := tx.Query(ctx, "SELECT feature_key, released_at FROM entitlement.feature_release ORDER BY feature_key LIMIT $1", loadLimit)
	if err != nil {
		return nil, store.Sanitize("read the entitlement feature releases", err)
	}
	defer rows.Close()
	var releases []FeatureReleaseFact
	for rows.Next() {
		var release FeatureReleaseFact
		var at time.Time
		if err = rows.Scan(&release.Feature, &at); err != nil {
			return nil, store.Sanitize("read the entitlement feature releases", err)
		}
		release.ReleasedAt = FromTime(at)
		releases = append(releases, release)
	}
	return releases, store.Sanitize("read the entitlement feature releases", rows.Err())
}

// LoadSnapshot reads only the stored snapshot of an account (the gate's fast path: no record is read when the snapshot is valid) and
// its revision.
func LoadSnapshot(ctx context.Context, tx pgx.Tx, account string) (*StoredSnapshot, error) {
	var snapshot StoredSnapshot
	var computed time.Time
	var valid *time.Time
	err := tx.QueryRow(ctx, "SELECT entitlement_version, computed_at, valid_until, definitions_version, content FROM entitlement.snapshot WHERE account_id = $1::uuid",
		account).Scan(&snapshot.Version, &computed, &valid, &snapshot.DefinitionsVersion, &snapshot.Content)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, store.Sanitize("read the entitlement snapshot", err)
	}
	snapshot.AccountID, snapshot.ComputedAt, snapshot.ValidUntil = account, FromTime(computed), optionalMicros(valid)
	return &snapshot, nil
}

// Commit appends the records and replaces the snapshot as one unit of work within the caller's transaction, guarded by the account's
// revision: it returns RevisionConflict, having written nothing, when the account is no longer at the revision the caller loaded.
// A constraint refusal or any other store failure is an error and the caller's transaction must roll back.
func Commit(ctx context.Context, tx pgx.Tx, account string, expected int64, add Append, snapshot Snapshot, at time.Time) (CommitOutcome, error) {
	if expected == 0 {
		// The first commit of an account creates its fence row; of two simultaneous first commits the second finds the row and writes nothing.
		tag, err := tx.Exec(ctx, "INSERT INTO entitlement.revision (account_id, rev, updated_at) VALUES ($1::uuid, 1, $2) ON CONFLICT (account_id) DO NOTHING", account, at)
		if err != nil {
			return 0, store.Sanitize("advance the entitlement revision", err)
		}
		if tag.RowsAffected() != 1 {
			return RevisionConflict, nil
		}
	} else {
		tag, err := tx.Exec(ctx, "UPDATE entitlement.revision SET rev = rev + 1, updated_at = $2 WHERE account_id = $1::uuid AND rev = $3", account, at, expected)
		if err != nil {
			return 0, store.Sanitize("advance the entitlement revision", err)
		}
		if tag.RowsAffected() != 1 {
			return RevisionConflict, nil
		}
	}
	for _, grant := range add.Grants {
		value, err := encodeValue(grant.Value)
		if err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO entitlement.grant (grant_id, account_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at, reason)
VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12)`, grant.GrantID, account, int16(grant.Kind)+1, grant.Subject, string(value), int16(grant.Source)+1,
			grant.SourceRef, grant.EffectiveFrom.Time(), optionalTime(grant.EffectiveUntil), grant.IssuedByActor, grant.CreatedAt.Time(), grant.Reason); err != nil {
			return 0, store.Sanitize("append an entitlement grant", err)
		}
	}
	for _, revocation := range add.Revocations {
		if _, err := tx.Exec(ctx, `INSERT INTO entitlement.revocation (revocation_id, account_id, grant_id, reason_code, effective_from, issued_by_actor, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)`, revocation.RevocationID, account, revocation.GrantID, revocation.ReasonCode, revocation.EffectiveFrom.Time(),
			revocation.IssuedByActor, revocation.CreatedAt.Time()); err != nil {
			return 0, store.Sanitize("append an entitlement revocation", err)
		}
	}
	for _, term := range add.Terms {
		if _, err := tx.Exec(ctx, `INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, authorized_at, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)`, term.Fact.TermID, account, int16(term.Fact.Kind)+1, term.SubscriptionRef, term.PeriodRef, term.Fact.StartsAt.Time(),
			term.Fact.EndsAt.Time(), optionalTime(term.Fact.GraceEndsAt), term.Fact.AuthorizedAt.Time(), term.Fact.CreatedAt.Time()); err != nil {
			return 0, store.Sanitize("append an entitlement service term", err)
		}
	}
	for _, activation := range add.Activations {
		if _, err := tx.Exec(ctx, "INSERT INTO entitlement.definitions_activation (account_id, activated_at, definitions_version) VALUES ($1::uuid, $2, $3)",
			account, activation.ActivatedAt.Time(), activation.Version); err != nil {
			return 0, store.Sanitize("append an entitlement definitions activation", err)
		}
	}
	stored := snapshot.Stored()
	if _, err := tx.Exec(ctx, `INSERT INTO entitlement.snapshot (account_id, entitlement_version, computed_at, valid_until, definitions_version, content)
VALUES ($1::uuid, $2, $3, $4, $5, $6)
ON CONFLICT (account_id) DO UPDATE SET entitlement_version = excluded.entitlement_version, computed_at = excluded.computed_at, valid_until = excluded.valid_until,
    definitions_version = excluded.definitions_version, content = excluded.content`, account, stored.Version, stored.ComputedAt.Time(), optionalTime(stored.ValidUntil),
		stored.DefinitionsVersion, stored.Content); err != nil {
		return 0, store.Sanitize("store the entitlement snapshot", err)
	}
	return Committed, nil
}
