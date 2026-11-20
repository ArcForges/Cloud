// SPDX-License-Identifier: AGPL-3.0-only
package commerce

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

type Environment = paddle.Environment
type Event = paddle.Event

// Provider is the Paddle Billing v1 boundary. A read that finds nothing does
// not prove an uncertain write never reached the provider.
type Provider interface {
	CreateCheckout(context.Context, paddle.CheckoutRequest) (paddle.Transaction, error)
	FindCheckout(context.Context, paddle.CheckoutRequest) (paddle.Transaction, bool, error)
	GetTransaction(context.Context, string) (paddle.Transaction, error)
	GetSubscription(context.Context, string) (paddle.Subscription, error)
	GetAdjustment(context.Context, string) (paddle.Adjustment, error)
	ListAdjustments(context.Context, string) ([]paddle.Adjustment, error)
	ListTransactionsBySubscription(context.Context, string) ([]paddle.Transaction, error)
	CancelAtPeriodEnd(context.Context, string) (paddle.Subscription, error)
	ResumeRenewal(context.Context, string) (paddle.Subscription, error)
	CreatePortal(context.Context, string, string) (string, error)
}

const AdjustmentPolicy = "preserve_partial_end_full_or_chargeback"

type Catalogue struct {
	Version          string
	SalesOpen        bool
	CheckoutLifetime time.Duration
	Offers           []Offer
}

type Offer struct {
	ID                                                   platform.ID
	PriceVersion, PriceID, ProductID, DefinitionsVersion string
	Currency, Interval, Region, AdjustmentPolicy         string
	AmountMinor                                          int64
}

type Options struct {
	DB           *store.DB
	Provider     Provider
	Environment  Environment
	Catalogue    Catalogue
	Entitlements *entitlement.Service
	Clock        func() time.Time
}

type Service struct {
	db            *store.DB
	provider      Provider
	environment   paddle.Environment
	environmentID int16
	catalogue     Catalogue
	entitlements  *entitlement.Service
	clock         func() time.Time
}

var (
	idText       = regexp.MustCompile("^[a-zA-Z0-9._:-]{1,128}$")
	currencyCode = regexp.MustCompile("^[A-Z]{3}$")
	regionCode   = regexp.MustCompile("^[A-Z]{2}$")
)

func NewService(options Options) (*Service, error) {
	if options.DB == nil || options.Provider == nil || options.Entitlements == nil {
		return nil, errors.New("commerce requires a runtime store, provider and entitlement service")
	}
	var environmentID int16
	switch options.Environment {
	case paddle.Live:
		environmentID = 1
	case paddle.Sandbox:
		environmentID = 2
	default:
		return nil, errors.New("commerce requires an admitted provider environment")
	}
	catalogue := options.Catalogue
	if !idText.MatchString(catalogue.Version) || catalogue.CheckoutLifetime <= 0 ||
		catalogue.CheckoutLifetime > 24*time.Hour || len(catalogue.Offers) == 0 || len(catalogue.Offers) > 64 {
		return nil, errors.New("commerce catalogue has invalid version, lifetime or offer bounds")
	}
	offers := make(map[platform.ID]bool, len(catalogue.Offers))
	prices := make(map[string]bool, len(catalogue.Offers))
	for _, offer := range catalogue.Offers {
		if offer.ID == (platform.ID{}) || offers[offer.ID] || prices[offer.PriceID] ||
			!idText.MatchString(offer.PriceVersion) || !idText.MatchString(offer.DefinitionsVersion) ||
			!strings.HasPrefix(offer.PriceID, "pri_") || !idText.MatchString(offer.PriceID) ||
			!strings.HasPrefix(offer.ProductID, "pro_") || !idText.MatchString(offer.ProductID) ||
			!currencyCode.MatchString(offer.Currency) || offer.AmountMinor <= 0 ||
			(offer.Interval != "month" && offer.Interval != "year") ||
			!regionCode.MatchString(offer.Region) || offer.AdjustmentPolicy != AdjustmentPolicy {
			return nil, errors.New("commerce catalogue contains an invalid or ambiguous offer")
		}
		offers[offer.ID] = true
		prices[offer.PriceID] = true
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	catalogue.Offers = slices.Clone(catalogue.Offers)
	return &Service{db: options.DB, provider: options.Provider, environment: options.Environment,
		environmentID: environmentID, catalogue: catalogue, entitlements: options.Entitlements, clock: options.Clock}, nil
}

func (s *Service) GetCatalogue() Catalogue {
	result := s.catalogue
	result.Offers = slices.Clone(result.Offers)
	return result
}

type Actor struct {
	Account, Session, Device, Correlation platform.ID
	AuthEpoch, RecoveryGeneration         int64
	Browser                               bool
}

type PurchaseRequest struct {
	CommandID, PurchaseID, OfferID platform.ID
	PriceVersion, Region           string
	CommandPayload                 []byte
}

type CheckoutAttemptRequest struct {
	CommandID, PurchaseID, CheckoutID platform.ID
	ReturnPath                        string
	CommandPayload                    []byte
}

type RenewalRequest struct {
	CommandID, SubscriptionID platform.ID
	AutoRenew                 bool
	ExpectedRevision          int64
	CommandPayload            []byte
}

type Purchase struct {
	ID, OfferID         platform.ID
	State, PriceVersion string
	Revision            int64
	ExpiresAt           time.Time
}

type Checkout struct {
	ID, PurchaseID platform.ID
	State, URL     string
	ExpiresAt      time.Time
}

type SubscriptionView struct {
	ID                      platform.ID
	State, CatalogueVersion string
	PeriodStart, PeriodEnd  time.Time
	AutoRenew               bool
	Revision                int64
}

type BillingQuery struct {
	From, Until, Before time.Time
	BeforeID            platform.ID
	Limit               int
}

type BillingEntry struct {
	ID             platform.ID
	Kind, Currency string
	AmountMinor    int64
	OccurredAt     time.Time
}

type BillingPage struct {
	Items   []BillingEntry
	HasMore bool
}

type EventReceipt struct {
	Duplicate bool
	State     string
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) findOffer(id platform.ID) (Offer, bool) {
	for _, offer := range s.catalogue.Offers {
		if offer.ID == id {
			return offer, true
		}
	}
	return Offer{}, false
}

func lockAccount(ctx context.Context, tx pgx.Tx, account platform.ID) (session.AccountSecurity, error) {
	var known bool
	if err := tx.QueryRow(ctx, "SELECT true FROM identity.user WHERE user_id=$1 FOR UPDATE", account).Scan(&known); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return session.AccountSecurity{}, arc.CredentialRevoked()
		}
		return session.AccountSecurity{}, err
	}
	return session.LockAccountSecurity(ctx, tx, account)
}

func actorCurrent(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time, lock bool) error {
	if !actor.Browser || actor.Account == (platform.ID{}) || actor.Session == (platform.ID{}) || actor.Device == (platform.ID{}) ||
		actor.AuthEpoch < 0 || actor.RecoveryGeneration < 0 {
		return arc.PermissionDenied("commerce")
	}
	if lock {
		security, err := lockAccount(ctx, tx, actor.Account)
		if err != nil {
			return err
		}
		if !security.AdmitsScope(session.ScopeAccount) ||
			int64(security.AuthEpoch) != actor.AuthEpoch || int64(security.RecoveryGeneration) != actor.RecoveryGeneration {
			return arc.CredentialRevoked()
		}
	}
	var live bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.session s
JOIN identity.user u ON u.user_id=s.user_id JOIN identity.account_security_state a ON a.user_id=u.user_id
JOIN device.device d ON d.device_id=s.device_id JOIN device.installation i ON i.installation_id=s.installation_id
WHERE s.user_id=$1 AND s.session_id=$2 AND s.scope=$3 AND s.credential_kind=2
AND u.state IN (1,2) AND a.auth_epoch=$4 AND a.recovery_generation=$5
AND s.auth_epoch=$4 AND s.recovery_generation=$5
AND s.revoked_at IS NULL AND d.revoked_at IS NULL AND i.revoked_at IS NULL
AND s.device_id=$7 AND s.expires_at>$6 AND s.idle_expires_at>$6)`,
		actor.Account, actor.Session, int16(session.ScopeAccount), actor.AuthEpoch, actor.RecoveryGeneration, now, actor.Device).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return arc.CredentialRevoked()
	}
	return nil
}

const commerceProcedure = "/arcforges.publicapi.v1.CommerceService/"

// reserve returns send authority only when this invocation committed the
// guarded reservation. An uncertain database commit cannot authorize I/O.
func (s *Service) reserve(ctx context.Context, actor Actor, command platform.ID, method string, payload []byte,
	run func(context.Context, pgx.Tx, time.Time, [32]byte) (bool, error)) (bool, error) {
	if command == (platform.ID{}) || len(payload) == 0 || len(payload) > 64<<10 {
		return false, arc.InvalidArgument("meta.command_id", "commerce_command")
	}
	outcome, err := platform.Execute(ctx, s.db, platform.Command{
		Principal: actor.Account.String(), CommandID: command, Operation: commerceProcedure + method, Request: payload,
	}, store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		now := s.now()
		if err := actorCurrent(ctx, tx, actor, now, true); err != nil {
			return nil, err
		}
		claimed, err := run(ctx, tx, now, sha256.Sum256(payload))
		if err != nil || !claimed {
			return nil, err
		}
		return []byte{1}, nil
	})
	if errors.Is(err, platform.ErrCommandIDReused) {
		return false, arc.CommandIDReused()
	}
	if err != nil {
		return false, err
	}
	return !outcome.Replayed && outcome.Succeeded && len(outcome.Result) == 1, nil
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, now time.Time, account platform.ID, name, target string,
	id platform.ID, command, correlation *platform.ID) error {
	_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now,
		ActorRef: account.String(), EventType: "commerce." + name, Reason: name,
		CorrelationID: correlation, CommandID: command, TargetKind: target, TargetID: id.String()})
	return err
}

func (s *Service) read(ctx context.Context, actor Actor, query func(context.Context, pgx.Tx, time.Time) error) error {
	return s.db.InTx(ctx, "read account commerce", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			if err := actorCurrent(ctx, tx, actor, now, false); err != nil {
				return err
			}
			return query(ctx, tx, now)
		})
}
