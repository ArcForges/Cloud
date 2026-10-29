// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Events counts the identity surface's outcomes for metrics (closed labels).
type Events interface {
	ObserveIdentity(event, outcome string)
}

type noEvents struct{}

func (noEvents) ObserveIdentity(string, string) {}

// Service is the account core of the identity surface: sign-in by passkey and e-mail code, the owner bootstrap and the account
// reads. Every refusal it returns is an *arc.Refusal; any other error is a store failure.
//
// Transactions per request (docs/postgres-store.md): a rate-limit count is its own short transaction before the work; a proof's
// attempt is taken in its own short transaction before the proof is checked; no transaction is open while a PBKDF2 code, a
// WebAuthn ceremony or the mail provider is verified or called; the success transaction ends with its audit event.
type Service struct {
	db        *store.DB
	policy    config.IdentityPolicy
	rp        *passkey.RelyingParty
	mailer    mail.Sender
	limits    *ratelimit.Limiter
	bootstrap *config.Bootstrap
	clock     func() time.Time
	events    Events
	logger    *slog.Logger
	// codeSlots bounds the PBKDF2 computations running at once (PLT-9).
	codeSlots chan struct{}
	// background runs the deliveries that follow a response.
	background func(func())
	// participants revoke what each holds for a device in the device revocation's transaction (DC-06).
	participants []device.Participant
}

// Options are the parts of a service.
type Options struct {
	DB        *store.DB
	Policy    config.IdentityPolicy
	RP        *passkey.RelyingParty
	Mail      mail.Sender
	Bootstrap *config.Bootstrap
	Clock     func() time.Time
	Events    Events
	Logger    *slog.Logger
	// Background runs a delivery after the response; nil runs it on a new goroutine.
	Background func(func())
	// Participants are the device revocation's cascade participants (none in AF-CTR-03; tests register a stand-in).
	Participants []device.Participant
}

// New is the service of a configuration.
func New(options Options) *Service {
	service := &Service{db: options.DB, policy: options.Policy, rp: options.RP, mailer: options.Mail, limits: ratelimit.New(options.DB),
		bootstrap: options.Bootstrap, clock: options.Clock, events: options.Events, logger: options.Logger, codeSlots: make(chan struct{}, 2),
		background: options.Background, participants: options.Participants}
	if service.mailer == nil {
		service.mailer = mail.Disabled{}
	}
	if service.clock == nil {
		service.clock = time.Now
	}
	if service.events == nil {
		service.events = noEvents{}
	}
	if service.logger == nil {
		service.logger = slog.New(slog.DiscardHandler)
	}
	if service.background == nil {
		service.background = func(work func()) { go work() }
	}
	return service
}

// Policy is the service's identity policy.
func (s *Service) Policy() config.IdentityPolicy { return s.policy }

// RelyingParty is the service's WebAuthn relying party.
func (s *Service) RelyingParty() *passkey.RelyingParty { return s.rp }

// MailEnabled reports whether the e-mail method is offered.
func (s *Service) MailEnabled() bool { return s.mailer.Enabled() }

// Request is what the identity surface knows about an anonymous call: the client's address (rate limits) and the correlation id
// (audit).
type Request struct {
	ClientIP      netip.Addr
	CorrelationID *platform.ID
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) bucket(kind ratelimit.Kind, key string) ratelimit.Bucket {
	return ratelimit.Bucket{Kind: kind, Key: key, Window: ratelimit.Window(s.policy, kind)}
}

// take counts a request bucket and refuses it over its limit; the first refusal of a window is audited, the rest are counted.
func (s *Service) take(ctx context.Context, request Request, bucket ratelimit.Bucket, actor string) error {
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if decision.Allowed {
		return nil
	}
	return s.limited(ctx, request, bucket, decision, actor)
}

// check refuses a failure bucket that holds its limit of failures (nothing is counted).
func (s *Service) check(ctx context.Context, request Request, bucket ratelimit.Bucket, actor string) error {
	decision, err := s.limits.Check(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if decision.Allowed {
		return nil
	}
	return s.limited(ctx, request, bucket, decision, actor)
}

func (s *Service) limited(ctx context.Context, request Request, bucket ratelimit.Bucket, decision ratelimit.Decision, actor string) error {
	s.events.ObserveIdentity("rate_limited", string(bucket.Kind))
	if decision.First {
		if err := s.auditAlone(ctx, request, actor, "identity.rate_limited", string(bucket.Kind), "rate_limit", "", map[string]any{"bucket": string(bucket.Kind)}); err != nil {
			return err
		}
	}
	return decision.Refusal(bucket)
}

// fail counts a failed proof in a failure bucket and audits it as audited decides.
func (s *Service) fail(ctx context.Context, request Request, bucket ratelimit.Bucket, actor, eventType, reason string, payload map[string]any) error {
	decision, err := s.limits.Fail(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	return s.audited(ctx, request, bucket, decision, actor, eventType, reason, payload)
}

// audited audits a counted failure once per window (E10). A failure that names an account is audited as the first failure of its
// bucket's window. An anonymous failure's bucket key is chosen by the client (an unknown credential, an address), so its audit
// follows the client's prefix instead: a marker of the bucket's kind keyed by the prefix is counted, and only its first failure of
// a window is audited; the rest are only counted. The marker is kept per class of failure (D3): "prefix:" for anonymous failures and
// "prefix-account:" for failures that name an account, so an account's failure never takes the anonymous failures' first audit of
// the prefix. Every failure counts exactly one marker, whoever it names, so known and unknown credentials run the same statements.
func (s *Service) audited(ctx context.Context, request Request, bucket ratelimit.Bucket, decision ratelimit.Decision, actor, eventType, reason string,
	payload map[string]any) error {
	class := "prefix:"
	if actor != Anonymous {
		class = "prefix-account:"
	}
	marker, err := s.limits.Fail(ctx, s.bucket(bucket.Kind, class+ratelimit.Prefix(request.ClientIP)), s.now())
	if err != nil {
		return err
	}
	if actor == Anonymous && marker.First || actor != Anonymous && decision.First {
		return s.auditAlone(ctx, request, actor, eventType, reason, "", "", payload)
	}
	return nil
}

func event(request Request, actor, eventType, reason, targetKind, targetID string, payload map[string]any, at time.Time) (platform.Event, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return platform.Event{}, err
	}
	return platform.Event{EventID: platform.NewID(), OccurredAt: at, ActorRef: actor, EventType: eventType, Reason: reason,
		CorrelationID: request.CorrelationID, TargetKind: targetKind, TargetID: targetID, Payload: data}, nil
}

// audit appends an event in the caller's transaction; it is the last statement before the commit.
func (s *Service) audit(ctx context.Context, tx pgx.Tx, request Request, actor, eventType, reason, targetKind, targetID string, payload map[string]any) error {
	item, err := event(request, actor, eventType, reason, targetKind, targetID, payload, s.now())
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, item)
	return err
}

// giveBack gives a failure reservation back after the transaction that would have given it back rolled back definitely (D2): best
// effort, in its own short auxiliary transaction. A caller never calls it after an unknown commit, because the give-back is not
// idempotent and that transaction may have committed.
func (s *Service) giveBack(ctx context.Context, bucket ratelimit.Bucket, reservation ratelimit.Decision) {
	_ = s.db.InTx(context.WithoutCancel(ctx), "give a failure reservation back", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true},
		func(ctx context.Context, tx pgx.Tx) error { return ratelimit.Release(ctx, tx, bucket, reservation) })
}

// auditAlone appends an event in its own transaction (a refusal's), which is auxiliary: the refusal is the call's answer, and the
// audit is no effect of it (D10).
func (s *Service) auditAlone(ctx context.Context, request Request, actor, eventType, reason, targetKind, targetID string, payload map[string]any) error {
	return s.db.InTx(ctx, "audit an identity refusal", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		return s.audit(ctx, tx, request, actor, eventType, reason, targetKind, targetID, payload)
	})
}

// Anonymous is the actor of a call without an account.
const Anonymous = "anonymous"

// Actor is the actor reference of an account.
func Actor(userID platform.ID) string { return "account:" + userID.String() }

// refusalOf returns the refusal an error carries, or nil.
func refusalOf(err error) *arc.Refusal {
	var refusal *arc.Refusal
	if errors.As(err, &refusal) {
		return refusal
	}
	return nil
}
