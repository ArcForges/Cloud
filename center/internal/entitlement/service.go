// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// RefusalKind is why the service refused a call: the typed refusals of the C# EntitlementError.
type RefusalKind int

// The refusals, in the C# declaration order.
const (
	RefusedInvalidRequest RefusalKind = iota + 1
	RefusedInvalidHistory
	RefusedConflict
	RefusedStaleVersion
	RefusedUnknownGrant
	RefusedConcurrentUpdate
	// RefusedOutcomeUnknown: the store could not tell whether the commit happened; only the same request may be sent again.
	RefusedOutcomeUnknown
)

func (k RefusalKind) String() string {
	switch k {
	case RefusedInvalidRequest:
		return "InvalidRequest"
	case RefusedInvalidHistory:
		return "InvalidHistory"
	case RefusedConflict:
		return "Conflict"
	case RefusedStaleVersion:
		return "StaleVersion"
	case RefusedUnknownGrant:
		return "UnknownGrant"
	case RefusedConcurrentUpdate:
		return "ConcurrentUpdate"
	case RefusedOutcomeUnknown:
		return "OutcomeUnknown"
	}
	return fmt.Sprintf("RefusalKind(%d)", int(k))
}

// Refusal is a typed refusal with a reason a caller or operator can read. Its Detail is never a value of the request.
type Refusal struct {
	Kind   RefusalKind
	Detail string
}

func (r *Refusal) Error() string { return "entitlement: " + r.Kind.String() + ": " + r.Detail }

func refuse(kind RefusalKind, detail string) error { return &Refusal{Kind: kind, Detail: detail} }

// RefusalOf is the typed refusal in an error chain.
func RefusalOf(err error) (*Refusal, bool) {
	var refusal *Refusal
	return refusal, errors.As(err, &refusal)
}

// DefinitionSource supplies the active definition set. The catalogue (feature package) stands behind it; the resolver never loads or
// validates configuration (CG-01).
type DefinitionSource interface{ Current() Definitions }

// IDSource allocates the identifiers of new grants and revocations; it is a port so the service stays deterministic under test.
type IDSource interface{ NewID() string }

type randomIDs struct{}

func (randomIDs) NewID() string { return platform.NewID().String() }

// attempts is how many times a call re-derives its snapshot after losing the race for the account's revision.
const attempts = 4

const unknownDetail = "The store could not tell whether the commit happened; send the same request again."

// Service is the single reader and writer of grants, revocations and snapshots (MB-04). Time comes only from the injected clock and
// never moves backwards past a stored computation (EN-08, RF-02); the snapshot and the records that justify it commit atomically; and
// every refusal is a typed *Refusal. It holds no state of its own, so any replica produces the same answer provided every replica
// reads the one authoritative time source: a replica whose clock runs ahead can move an account's stored computation forward for
// every other replica (docs/entitlement-resolver.md).
type Service struct {
	db          *store.DB
	definitions DefinitionSource
	ids         IDSource
	clock       func() time.Time
	// beforeCommit runs after a load and before the commit decision, to interleave another writer deterministically in a test.
	beforeCommit func()
	// onLoad runs before every load of an account's whole state (tests count the slow path with it).
	onLoad func()
}

// NewService is the service over a store. A nil clock reads the system clock; a nil id source draws random uuids.
func NewService(db *store.DB, definitions DefinitionSource, ids IDSource, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	if ids == nil {
		ids = randomIDs{}
	}
	return &Service{db: db, definitions: definitions, ids: ids, clock: clock}
}

// DefinitionsVersion is the version of the service's active definitions.
func (s *Service) DefinitionsVersion() string { return s.definitions.Current().Version }

// Clock is the service's time source.
func (s *Service) Clock() time.Time { return s.clock() }

// validAccount reports an account identifier the store can serve: an opaque identifier that is a canonical uuid, because the store
// keys an account by uuid. Any other token is refused as a malformed identifier before a read, instead of failing in the database as
// an internal error.
func validAccount(account string) bool {
	return IsIdentifier(account) && correlation.IDBytes(account) != nil
}

// malformedText is the refusal of a request whose text is not valid UTF-8 (the C# port adapter's well-formedness rule): PostgreSQL
// refuses such bytes with an untyped error, so the service refuses them first, and typedConstraint answers the same for a writer that
// reaches the store without passing here.
const malformedText = "The request holds text that is not valid UTF-8."

// wellFormed reports that none of the texts holds bytes that are not valid UTF-8.
func wellFormed(texts ...string) bool {
	for _, text := range texts {
		if !WellFormedText(text) {
			return false
		}
	}
	return true
}

func (s *Service) load(ctx context.Context, account string) (State, error) {
	if s.onLoad != nil {
		s.onLoad()
	}
	var state State
	err := s.db.InTx(ctx, "load the entitlement state", store.TxOptions{ReadOnly: true, Isolation: pgx.RepeatableRead}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		state, err = Load(ctx, tx, account)
		return err
	})
	return state, err
}

// ErrDefinitionsSuperseded is why a replica neither recomputes nor writes an account (AF-CTR-05 E0, store-1): its definitions version
// is not the deploy-level fact's (entitlement.definitions_current), which the revision that started last recorded. Two revisions with
// different definitions versions running side by side (a rolling deploy) would otherwise each recompute and append an activation at
// every read of an account whose last activation is the other's, and the 2000-record bound would wedge the account. A read of such a
// replica returns the stored snapshot as it is while it is valid; a read that needs a recompute, and every write, is this error, which
// the gate answers as RESOURCE/overloaded (access.gate_failure, definitions_superseded).
var ErrDefinitionsSuperseded = errors.New("the definitions version of this replica is not the deploy's current one")

// mayCompute reports whether the service may recompute or write an account of the state: no center recorded a current definitions
// version yet, or it recorded the service's own.
func mayCompute(state State, definitions Definitions) bool {
	return state.CurrentDefinitions == "" || state.CurrentDefinitions == definitions.Version
}

// Recording is what RecordDefinitions found.
type Recording int

// The recordings.
const (
	// Recorded: the fact now holds the service's version from this start (it was absent, or held another version from an older start).
	Recorded Recording = iota + 1
	// AlreadyRecorded: the fact held the service's version already; nothing was written (the row keeps its instant).
	AlreadyRecorded
	// Superseded: the fact holds another version, recorded by a start at or after this one's (a newer revision started while this one
	// could not record): nothing was written, and this replica neither recomputes nor writes from now on.
	Superseded
)

// RecordDefinitions records the service's definitions version as the deploy-level fact (store-1): the revision that starts with a
// version writes it at its start, before it serves, stamped with its start instant (startedAt, captured once before the first
// attempt and passed unchanged to every retry). The row is replaced only by another version from a newer start (the trigger refuses
// anything else): a retry of an older revision that lands after a newer revision recorded writes nothing and reports Superseded, so a
// late retry never displaces the newer fact (B-1 of the review of Cloud #143). The same version is never written twice. A replica
// whose version is not the fact's neither recomputes nor writes, so the activations an account can gain are bounded by the starts
// that change the version, never by its reads. An older revision that restarts during a rolling deploy is a newer start and records
// its version again; restarting the newer revision recovers (docs/center-entitlement.md).
func (s *Service) RecordDefinitions(ctx context.Context, startedAt time.Time) (Recording, error) {
	version := s.definitions.Current().Version
	at := FromTime(startedAt).Time()
	var recording Recording
	err := s.db.InTx(ctx, "record the current definitions version", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO entitlement.definitions_current AS c (singleton, definitions_version, recorded_at) VALUES (true, $1, $2)
ON CONFLICT (singleton) DO UPDATE SET definitions_version = excluded.definitions_version, recorded_at = excluded.recorded_at
WHERE c.definitions_version <> excluded.definitions_version AND c.recorded_at < excluded.recorded_at`, version, at)
		if err != nil {
			return store.Sanitize("record the current definitions version", err)
		}
		if tag.RowsAffected() == 1 {
			recording = Recorded
			return nil
		}
		current, err := LoadCurrentDefinitions(ctx, tx)
		if err != nil {
			return err
		}
		recording = Superseded
		if current == version {
			recording = AlreadyRecorded
		}
		return nil
	})
	return recording, err
}

// Read is the current snapshot of an account. A stored snapshot is returned while its validity holds; otherwise it is recomputed and
// stored. A snapshot computed under other definitions than the active ones is recomputed too.
func (s *Service) Read(ctx context.Context, account string) (StoredSnapshot, error) {
	if !validAccount(account) {
		return StoredSnapshot{}, refuse(RefusedInvalidRequest, "The workspace identifier is malformed.")
	}
	// The fast path reads the snapshot row, the deploy-level fact and the account's floor in one read-only transaction: the records are
	// read only when the snapshot has to be recomputed. Its validity is checked at the floor (State.Floor: never behind the newest
	// record, N-2 of the review of Cloud #143), and a replica whose definitions are superseded returns a valid stored snapshot from
	// here, whatever definitions it was computed under, instead of loading every record on every read (N-5): it may not recompute it
	// anyway (store-1).
	var stored *StoredSnapshot
	var current string
	var floor Micros
	var held bool
	err := s.db.InTx(ctx, "read the entitlement snapshot", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if stored, err = LoadSnapshot(ctx, tx, account); err != nil || stored == nil {
			return err
		}
		if current, err = LoadCurrentDefinitions(ctx, tx); err != nil {
			return err
		}
		floor, held, err = LoadFloor(ctx, tx, account)
		return err
	})
	if err != nil {
		return StoredSnapshot{}, err
	}
	if stored != nil {
		now := maxMicros(FromTime(s.clock()), stored.ComputedAt)
		if held {
			now = maxMicros(now, floor)
		}
		version := s.definitions.Current().Version
		superseded := current != "" && current != version
		if (stored.DefinitionsVersion == version || superseded) && (stored.ValidUntil == nil || now < *stored.ValidUntil) {
			return *stored, nil
		}
	}
	return s.Refresh(ctx, account)
}

// Refresh recomputes the snapshot at the authoritative instant and stores it when it differs. This is what a validity sweeper calls.
func (s *Service) Refresh(ctx context.Context, account string) (StoredSnapshot, error) {
	if !validAccount(account) {
		return StoredSnapshot{}, refuse(RefusedInvalidRequest, "The workspace identifier is malformed.")
	}
	for range attempts {
		state, err := s.load(ctx, account)
		if err != nil {
			return StoredSnapshot{}, err
		}
		definitions := s.definitions.Current()
		if !mayCompute(state, definitions) {
			// store-1: a replica of superseded definitions reads the snapshot as stored while it is valid, and never recomputes it.
			now, err := s.instant(state, false)
			if err != nil {
				return StoredSnapshot{}, err
			}
			if state.Snapshot != nil && (state.Snapshot.ValidUntil == nil || now < *state.Snapshot.ValidUntil) {
				return *state.Snapshot, nil
			}
			return StoredSnapshot{}, ErrDefinitionsSuperseded
		}
		now, err := s.instant(state, needsActivation(state.Records, definitions))
		if err != nil {
			return StoredSnapshot{}, err
		}
		records, activations := withActivation(state.Records, definitions, now)
		snapshot, err := seal(state, records, definitions, now)
		if err != nil {
			return StoredSnapshot{}, err
		}
		stored := snapshot.Stored()
		// An unchanged account is not rewritten at every later instant: only a different effect, validity or definitions activation is.
		if len(activations) == 0 && state.Snapshot != nil && state.Snapshot.Version == stored.Version && state.Snapshot.SameEffectAs(stored) &&
			equalMicros(state.Snapshot.ValidUntil, stored.ValidUntil) {
			return *state.Snapshot, nil
		}
		outcome, err := s.commit(ctx, account, state.Revision, Append{Activations: activations}, snapshot)
		if err != nil {
			return StoredSnapshot{}, err
		}
		if outcome == Committed {
			return stored, nil
		}
	}
	return StoredSnapshot{}, refuse(RefusedConcurrentUpdate, "The account changed concurrently on every attempt.")
}

// IssueGrant issues a grant through the grant interface (EO-03) and commits it atomically with the snapshot that reflects it. The
// second result is true when an equal grant already existed and nothing was written (a replay by source reference).
func (s *Service) IssueGrant(ctx context.Context, request IssueGrantRequest) (Grant, bool, error) {
	if refusal := ValidateIssue(request); refusal != "" {
		return Grant{}, false, refuse(RefusedInvalidRequest, refusal)
	}
	if !validAccount(request.AccountID) {
		return Grant{}, false, refuse(RefusedInvalidRequest, "The workspace identifier is malformed.")
	}
	if !wellFormed(request.IssuedByActor, optionalText(request.Reason), optionalText(request.SourceRef), request.Subject) {
		return Grant{}, false, refuse(RefusedInvalidRequest, malformedText)
	}
	for range attempts {
		state, err := s.load(ctx, request.AccountID)
		if err != nil {
			return Grant{}, false, err
		}
		for _, existing := range state.Records.Grants {
			if existing.Source == request.Source && equalStrings(existing.SourceRef, request.SourceRef) {
				if IsSameIssuance(existing, request) {
					return existing, true, nil
				}
				return Grant{}, false, refuse(RefusedConflict, "The source reference was already used for a different grant.")
			}
		}
		definitions := s.definitions.Current()
		if !mayCompute(state, definitions) {
			return Grant{}, false, ErrDefinitionsSuperseded
		}
		now, err := s.instant(state, true)
		if err != nil {
			return Grant{}, false, err
		}
		grant := Grant{GrantID: s.ids.NewID(), AccountID: request.AccountID, Kind: request.Kind, Subject: request.Subject, Value: request.Value, Source: request.Source,
			SourceRef: request.SourceRef, EffectiveFrom: request.EffectiveFrom, EffectiveUntil: request.EffectiveUntil, IssuedByActor: request.IssuedByActor,
			CreatedAt: now, Reason: request.Reason}
		records, activations := withActivation(state.Records, definitions, now)
		records.Grants = append(append([]Grant(nil), records.Grants...), grant)
		snapshot, err := seal(state, records, definitions, now)
		if err != nil {
			return Grant{}, false, err
		}
		outcome, err := s.commit(ctx, request.AccountID, state.Revision, Append{Grants: []Grant{grant}, Activations: activations}, snapshot)
		if err != nil {
			return Grant{}, false, err
		}
		if outcome == Committed {
			return grant, false, nil
		}
	}
	return Grant{}, false, refuse(RefusedConcurrentUpdate, "The account changed concurrently on every attempt.")
}

// RevokeGrant revokes one exact grant. The caller names the snapshot version it decided against; a different stored version is a
// stale decision and nothing is written. A replay of the same revocation writes nothing: without an explicit effective instant, any
// earlier revocation of the grant with the same reason code is the same revocation.
func (s *Service) RevokeGrant(ctx context.Context, request RevokeGrantRequest) (Revocation, bool, error) {
	if !validAccount(request.AccountID) || !IsIdentifier(request.GrantID) || !IsKey(request.ReasonCode) || !IsActor(request.IssuedByActor) {
		return Revocation{}, false, refuse(RefusedInvalidRequest, "The revocation names a malformed workspace, grant, reason code or actor.")
	}
	if !wellFormed(request.IssuedByActor, request.ReasonCode) {
		return Revocation{}, false, refuse(RefusedInvalidRequest, malformedText)
	}
	for range attempts {
		state, err := s.load(ctx, request.AccountID)
		if err != nil {
			return Revocation{}, false, err
		}
		known := false
		for _, candidate := range state.Records.Grants {
			known = known || candidate.GrantID == request.GrantID
		}
		if !known {
			return Revocation{}, false, refuse(RefusedUnknownGrant, "No such grant exists in this workspace.")
		}
		var version int64
		if state.Snapshot != nil {
			version = state.Snapshot.Version
		}
		if version != request.ExpectedSnapshotVersion {
			return Revocation{}, false, refuse(RefusedStaleVersion, "The entitlement version changed since the caller decided.")
		}
		if !mayCompute(state, s.definitions.Current()) {
			return Revocation{}, false, ErrDefinitionsSuperseded
		}
		now, err := s.instant(state, true)
		if err != nil {
			return Revocation{}, false, err
		}
		for _, existing := range state.Records.Revocations {
			if existing.GrantID == request.GrantID && existing.ReasonCode == request.ReasonCode && (request.EffectiveFrom == nil || existing.EffectiveFrom == *request.EffectiveFrom) {
				return existing, true, nil
			}
		}
		effective := now
		if request.EffectiveFrom != nil {
			effective = *request.EffectiveFrom
		}
		definitions := s.definitions.Current()
		revocation := Revocation{RevocationID: s.ids.NewID(), GrantID: request.GrantID, ReasonCode: request.ReasonCode, EffectiveFrom: effective,
			IssuedByActor: request.IssuedByActor, CreatedAt: now}
		records, activations := withActivation(state.Records, definitions, now)
		records.Revocations = append(append([]Revocation(nil), records.Revocations...), revocation)
		snapshot, err := seal(state, records, definitions, now)
		if err != nil {
			return Revocation{}, false, err
		}
		outcome, err := s.commit(ctx, request.AccountID, state.Revision, Append{Revocations: []Revocation{revocation}, Activations: activations}, snapshot)
		if err != nil {
			return Revocation{}, false, err
		}
		if outcome == Committed {
			return revocation, false, nil
		}
	}
	return Revocation{}, false, refuse(RefusedConcurrentUpdate, "The account changed concurrently on every attempt.")
}

// RebuildStatus is the result of comparing a stored snapshot with one rebuilt from the records alone.
type RebuildStatus int

// The statuses.
const (
	// RebuildEqual: the snapshot rebuilt from the records alone equals the stored snapshot exactly, version included.
	RebuildEqual RebuildStatus = iota + 1
	// RebuildMismatch: the rebuild differs under the same definitions. This is a defect, never a refresh (EN-02).
	RebuildMismatch
	// RebuildDefinitionsChanged: the active definitions are not the ones the stored snapshot was computed under; a refresh records their activation.
	RebuildDefinitionsChanged
	// RebuildNoSnapshot: no snapshot is stored yet.
	RebuildNoSnapshot
)

// RebuildReport is the result of VerifyRebuild.
type RebuildReport struct {
	AccountID   string
	Status      RebuildStatus
	Stored      *StoredSnapshot
	Rebuilt     *StoredSnapshot
	Differences []string
}

// VerifyRebuild rebuilds the snapshot from the records alone, at the instant the stored one was computed, and compares them in full.
// A difference is a defect, not a refresh (EN-02): it is reported and nothing is overwritten.
func (s *Service) VerifyRebuild(ctx context.Context, account string) (RebuildReport, error) {
	if !validAccount(account) {
		return RebuildReport{}, refuse(RefusedInvalidRequest, "The workspace identifier is malformed.")
	}
	state, err := s.load(ctx, account)
	if err != nil {
		return RebuildReport{}, err
	}
	if state.Snapshot == nil {
		return RebuildReport{AccountID: account, Status: RebuildNoSnapshot}, nil
	}
	stored := *state.Snapshot
	definitions := s.definitions.Current()
	if len(state.Records.Activations) > 0 && LastActivation(state.Records).Version != definitions.Version {
		return RebuildReport{AccountID: account, Status: RebuildDefinitionsChanged, Stored: &stored}, nil
	}
	resolved, err := Resolve(state.Records, definitions, stored.ComputedAt)
	if err != nil {
		return RebuildReport{}, rebuildFailure(err)
	}
	rebuilt := resolved.Stored()
	if rebuilt.SameAs(stored) {
		return RebuildReport{AccountID: account, Status: RebuildEqual, Stored: &stored, Rebuilt: &rebuilt}, nil
	}
	status := RebuildMismatch
	if rebuilt.DefinitionsVersion != stored.DefinitionsVersion {
		status = RebuildDefinitionsChanged
	}
	return RebuildReport{AccountID: account, Status: status, Stored: &stored, Rebuilt: &rebuilt, Differences: differences(stored, rebuilt)}, nil
}

// rebuildFailure is the refusal of a history the resolver cannot interpret (the C# service lets the exception through).
func rebuildFailure(err error) error {
	var input *InputError
	if errors.As(err, &input) {
		return refuse(RefusedInvalidHistory, input.Message)
	}
	return err
}

func differences(stored, rebuilt StoredSnapshot) []string {
	var lines []string
	if stored.Version != rebuilt.Version {
		lines = append(lines, fmt.Sprintf("version: %d != %d", stored.Version, rebuilt.Version))
	}
	if stored.ComputedAt != rebuilt.ComputedAt {
		lines = append(lines, "computedAt differs")
	}
	if !equalMicros(stored.ValidUntil, rebuilt.ValidUntil) {
		lines = append(lines, "validUntil differs")
	}
	left, right := splitLines(stored.Content), splitLines(rebuilt.Content)
	for _, line := range left {
		if !contains(right, line) {
			lines = append(lines, "stored only: "+line)
		}
	}
	for _, line := range right {
		if !contains(left, line) {
			lines = append(lines, "rebuilt only: "+line)
		}
	}
	return lines
}

func splitLines(text string) []string {
	var lines []string
	start := 0
	for index := range len(text) {
		if text[index] == '\n' {
			lines = append(lines, text[start:index])
			start = index + 1
		}
	}
	return append(lines, text[start:])
}

func contains(lines []string, line string) bool {
	for _, candidate := range lines {
		if candidate == line {
			return true
		}
	}
	return false
}

// instant is the instant a call computes at, floored at the newest instant the account holds (State.Floor: the stored computation,
// every record's creation, every activation and the revision's last commit; AF-CTR-05 E0, CTR5-GATE-02). A read that only checks
// validity uses Now, never behind the floor; a call that writes uses WriteNow: strictly after the floor, so no two admissions of one
// account share an instant and the version, which counts changes across instants, can never collapse or fall because two records
// arrived together.
func (s *Service) instant(state State, write bool) (Micros, error) {
	now := FromTime(s.clock())
	floor, found := state.Floor()
	if !found {
		return now, nil
	}
	if !write {
		return maxMicros(now, floor), nil
	}
	if floor == MaxMicros {
		return 0, ErrOverflow
	}
	return maxMicros(now, floor+1), nil
}

func needsActivation(records RecordSet, definitions Definitions) bool {
	return len(records.Activations) == 0 || LastActivation(records).Version != definitions.Version
}

// withActivation records the activation of the active definitions when the last activation names another version (the first one
// counts for nothing).
func withActivation(records RecordSet, definitions Definitions, now Micros) (RecordSet, []DefinitionsActivation) {
	if len(records.Activations) > 0 && LastActivation(records).Version == definitions.Version {
		return records, nil
	}
	added := DefinitionsActivation{Version: definitions.Version, ActivatedAt: now}
	records.Activations = append(append([]DefinitionsActivation(nil), records.Activations...), added)
	return records, []DefinitionsActivation{added}
}

// seal resolves the new snapshot and refuses one whose derived version fell below the stored version: that can only mean a record was
// admitted with a creation time before the stored computation, which would let a client's cached newer version outlive the truth.
// Owner admissions of terms, facts and releases must stamp the authoritative time.
func seal(state State, records RecordSet, definitions Definitions, now Micros) (Snapshot, error) {
	snapshot, err := Resolve(records, definitions, now)
	if err != nil {
		var input *InputError
		if errors.As(err, &input) {
			return Snapshot{}, refuse(RefusedInvalidHistory, input.Message)
		}
		return Snapshot{}, refuse(RefusedInvalidHistory, "The record history overflows the resolver's arithmetic.")
	}
	if state.Snapshot != nil && snapshot.Version < state.Snapshot.Version {
		return Snapshot{}, refuse(RefusedInvalidHistory, "The derived entitlement version fell below the stored version: a record was admitted with a creation time before the stored computation.")
	}
	return snapshot, nil
}

// Seal is seal for a caller that holds the state it loaded in its own transaction (the operator grant).
func Seal(state State, records RecordSet, definitions Definitions, now Micros) (Snapshot, error) {
	return seal(state, records, definitions, now)
}

// WithActivation is withActivation for a caller that builds its own commit.
func WithActivation(records RecordSet, definitions Definitions, now Micros) (RecordSet, []DefinitionsActivation) {
	return withActivation(records, definitions, now)
}

// WriteInstant is the instant a caller that writes in its own transaction admits its records at: strictly after the stored computation.
func WriteInstant(state State, clock time.Time) (Micros, error) {
	return (&Service{clock: func() time.Time { return clock }}).instant(state, true)
}

// commit stores one derived snapshot with its records in its own transaction and maps the outcome: a lost COMMIT without an answer is
// the typed OutcomeUnknown refusal, a lost race a RevisionConflict.
func (s *Service) commit(ctx context.Context, account string, expected int64, add Append, snapshot Snapshot) (CommitOutcome, error) {
	if s.beforeCommit != nil {
		hook := s.beforeCommit
		s.beforeCommit = nil
		hook()
	}
	var outcome CommitOutcome
	err := s.db.InTx(ctx, "store the entitlement snapshot", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		outcome, err = Commit(ctx, tx, account, expected, add, snapshot, s.clock())
		return err
	})
	switch {
	case errors.Is(err, store.ErrCommitUnknown):
		return 0, refuse(RefusedOutcomeUnknown, unknownDetail)
	case err != nil:
		return 0, typedConstraint(err)
	}
	return outcome, nil
}

// typedConstraint turns the two constraint refusals a caller's request can cause into the typed refusal of an invalid request: an
// account that has no identity.user row (the revision row's foreign key) and a reason recorded on a source that is not administrative
// (the grant table's check, which the C# admission admits). Every other failure is returned as it is.
func typedConstraint(err error) error {
	var stored *store.Error
	if !errors.As(err, &stored) {
		return err
	}
	switch {
	case stored.SQLState == "23503" && stored.Constraint == "revision_account":
		return refuse(RefusedInvalidRequest, "The account does not exist.")
	case stored.SQLState == "22021":
		return refuse(RefusedInvalidRequest, malformedText)
	case stored.SQLState == "23514" && stored.Constraint == "grant_reason_required_for_operator_sources":
		return refuse(RefusedInvalidRequest, "A reason is recorded only for an administrative source, and an administrative source needs one.")
	}
	return err
}
