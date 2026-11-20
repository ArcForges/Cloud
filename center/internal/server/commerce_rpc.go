// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"golang.org/x/text/currency"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	billingReturnPath = "/account/subscription"
	billingListing    = page.Listing(4)
)

type commerceRPC struct {
	service    *commerce.Service
	authorizer *access.Authorizer
	clock      func() time.Time
}

type commerceInput struct {
	actor   commerce.Actor
	command platform.ID
	bytes   []byte
}

func (s commerceRPC) methods() []connect.Method {
	return []connect.Method{
		commerceMethod(s, "GetCatalogue", publicapiv1connect.CommerceServiceGetCatalogueProcedure, s.getCatalogue, getCatalogueReply),
		commerceMethod(s, "CreatePurchaseIntent", publicapiv1connect.CommerceServiceCreatePurchaseIntentProcedure, s.createPurchase, createPurchaseReply),
		commerceMethod(s, "CreateCheckoutAttempt", publicapiv1connect.CommerceServiceCreateCheckoutAttemptProcedure, s.createCheckout, createCheckoutReply),
		commerceMethod(s, "GetPurchaseState", publicapiv1connect.CommerceServiceGetPurchaseStateProcedure, s.getPurchase, getPurchaseReply),
		commerceMethod(s, "GetSubscription", publicapiv1connect.CommerceServiceGetSubscriptionProcedure, s.getSubscription, getSubscriptionReply),
		commerceMethod(s, "CancelSubscription", publicapiv1connect.CommerceServiceCancelSubscriptionProcedure, s.cancelSubscription, cancelSubscriptionReply),
		commerceMethod(s, "ReactivateSubscription", publicapiv1connect.CommerceServiceReactivateSubscriptionProcedure, s.reactivateSubscription, reactivateSubscriptionReply),
		commerceMethod(s, "ListBillingHistory", publicapiv1connect.CommerceServiceListBillingHistoryProcedure, s.listBilling, listBillingReply),
	}
}

func commerceMethod[Request any, PRequest interface {
	*Request
	proto.Message
	GetMeta() *foundationv1.RequestMeta
}, Value, Response proto.Message](rpc commerceRPC, name, procedure string, handle func(context.Context, commerceInput, PRequest) (Value, error),
	reply func(*foundationv1.ResponseMeta, Value, *foundationv1.ArcError) Response) connect.Method {
	return connect.Method{
		Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary,
			Schema: publicapiv1.File_arcforges_publicapi_v1_commerce_proto.Services().ByName("CommerceService").Methods().ByName(protoreflect.Name(name))},
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			request := PRequest(new(Request))
			if err := stream.Receive(request); err != nil {
				return err
			}
			call, ok := ingress.CallFrom(ctx)
			if !ok {
				return connect.NewError(connect.CodeInternal, "the commerce call was not admitted")
			}
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			input, err := rpc.authorize(ctx, call, request, request.GetMeta())
			var value Value
			if err == nil {
				value, err = handle(ctx, input, request)
			}
			return stream.Send(reply(ingress.ResponseMeta(call.Correlation), value, rpc.failure(call, err)))
		},
	}
}

func (s commerceRPC) authorize(ctx context.Context, call *ingress.Call, request proto.Message, meta *foundationv1.RequestMeta) (commerceInput, error) {
	operation, err := s.authorizer.Authorize(ctx, call)
	if err != nil {
		return commerceInput{}, err
	}
	actor, err := commerceActor(call)
	if err != nil {
		return commerceInput{}, err
	}
	if meta == nil || len(request.ProtoReflect().GetUnknown()) != 0 || len(meta.ProtoReflect().GetUnknown()) != 0 {
		return commerceInput{}, arc.InvalidArgument("request", "typed_message_invalid")
	}
	if meta.WorkspaceId != nil || meta.ExpectedNative != nil || meta.ApplicationScope != nil {
		return commerceInput{}, arc.InvalidArgument("meta", "account_scope_required")
	}
	if meta.RecoveryGeneration != nil && meta.GetRecoveryGeneration() != call.Caller.RecoveryGeneration {
		return commerceInput{}, arc.CredentialRevoked()
	}
	renewal := call.Policy.FullName == publicapiv1connect.CommerceServiceCancelSubscriptionProcedure ||
		call.Policy.FullName == publicapiv1connect.CommerceServiceReactivateSubscriptionProcedure
	if !renewal && meta.ExpectedRev != nil {
		return commerceInput{}, arc.InvalidArgument("meta.expected_rev", "not_admitted")
	}
	input := commerceInput{actor: actor}
	if !operation.Receipt {
		if meta.CommandId != nil {
			return commerceInput{}, arc.InvalidArgument("meta.command_id", "not_admitted")
		}
		return input, nil
	}
	if input.command, err = commerceID(meta.CommandId, "meta.command_id"); err != nil {
		return commerceInput{}, err
	}
	input.bytes, err = platform.RequestDigestInput(call.Message)
	if err != nil {
		return commerceInput{}, arc.InvalidArgument("request", "typed_message_invalid")
	}
	return input, nil
}

func commerceActor(call *ingress.Call) (commerce.Actor, error) {
	actor := commerce.Actor{
		Account: commerceTextID(call.Caller.UserID), Session: commerceTextID(call.Caller.SessionID),
		Device: commerceTextID(call.Caller.DeviceID), Correlation: commerceTextID(call.Correlation.CorrelationID),
		AuthEpoch: call.Caller.AuthEpoch, RecoveryGeneration: int64(call.Caller.RecoveryGeneration),
		Browser: call.Caller.Credential == ingress.CredentialBrowserSession,
	}
	if actor.Account == (platform.ID{}) || actor.Session == (platform.ID{}) || actor.Device == (platform.ID{}) ||
		!actor.Browser || call.Caller.RecoveryGeneration > math.MaxInt64 {
		return commerce.Actor{}, arc.Unauthenticated()
	}
	return actor, nil
}

func (s commerceRPC) failure(call *ingress.Call, err error) *foundationv1.ArcError {
	if err == nil {
		return nil
	}
	return commerceRefusal(err).Dated(s.clock()).ArcError(call.Correlation)
}

func commerceRefusal(err error) *arc.Refusal {
	var refusal *arc.Refusal
	switch {
	case errors.As(err, &refusal):
		return refusal
	case errors.Is(err, store.ErrCommitUnknown):
		return arc.Internal()
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, store.ErrTimeout), errors.Is(err, store.ErrContention),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return arc.Unavailable()
	default:
		return arc.Internal()
	}
}

func commerceTextID(value string) platform.ID {
	var id platform.ID
	copy(id[:], correlation.IDBytes(value))
	return id
}

func commerceID(value *foundationv1.Id, field string) (platform.ID, error) {
	var id platform.ID
	if value == nil || len(value.Value) != len(id) || len(value.ProtoReflect().GetUnknown()) != 0 {
		return id, arc.InvalidArgument(field, "required")
	}
	copy(id[:], value.Value)
	if id == (platform.ID{}) {
		return id, arc.InvalidArgument(field, "required")
	}
	return id, nil
}

func wireCommerceID(id platform.ID) *foundationv1.Id { return &foundationv1.Id{Value: id[:]} }

func wireCommerceRevision(value int64) *foundationv1.Revision {
	return &foundationv1.Revision{Value: proto.Int64(value)}
}

func regionCode(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func commerceMoney(value int64, code string) (*foundationv1.Decimal, bool) {
	unit, err := currency.ParseISO(code)
	if err != nil || unit.String() != code {
		return nil, false
	}
	digits, _ := currency.Standard.Rounding(unit)
	number := strconv.FormatInt(value, 10)
	if digits == 0 {
		return &foundationv1.Decimal{Value: proto.String(number)}, true
	}
	absolute := strings.TrimPrefix(number, "-")
	absolute = strings.Repeat("0", max(0, digits+1-len(absolute))) + absolute
	point := len(absolute) - digits
	decimal := strings.TrimRight(strings.TrimRight(absolute[:point]+"."+absolute[point:], "0"), ".")
	if value < 0 {
		decimal = "-" + decimal
	}
	return &foundationv1.Decimal{Value: proto.String(decimal)}, true
}

func (s commerceRPC) getCatalogue(_ context.Context, _ commerceInput, request *publicapiv1.CommerceServiceGetCatalogueRequest) (*publicapiv1.CommerceServiceGetCatalogueValue, error) {
	region := request.GetRegion()
	if !regionCode(region) {
		return nil, arc.InvalidArgument("region", "country_code")
	}
	merchant := s.service.GetCatalogue()
	if !merchant.SalesOpen {
		return nil, arc.InvalidState("catalogue", "sales_closed")
	}
	result := &publicapiv1.CommerceServiceGetCatalogueValue{CatalogueVersion: proto.String(merchant.Version)}
	for _, offer := range merchant.Offers {
		if offer.Region != "" && offer.Region != region {
			continue
		}
		amount, ok := commerceMoney(offer.AmountMinor, offer.Currency)
		if !ok {
			return nil, arc.Internal()
		}
		result.Items = append(result.Items, &publicapiv1.Offer{
			OfferId: wireCommerceID(offer.ID), PriceVersion: proto.String(offer.PriceVersion), Kind: proto.String("subscription"),
			Currency: proto.String(offer.Currency), Amount: amount, Interval: proto.String(offer.Interval),
			Entitlements: config.GatedFeatureKeys(), Region: proto.String(region),
		})
	}
	return result, nil
}

func (s commerceRPC) createPurchase(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceCreatePurchaseIntentRequest) (*publicapiv1.CommerceServiceCreatePurchaseIntentValue, error) {
	purchaseID, err := commerceID(request.PurchaseIntentId, "purchase_intent_id")
	if err != nil {
		return nil, err
	}
	offerID, err := commerceID(request.OfferId, "offer_id")
	if err != nil {
		return nil, err
	}
	if !regionCode(request.GetRegion()) {
		return nil, arc.InvalidArgument("region", "country_code")
	}
	if request.GetPriceVersion() == "" || len(request.GetPriceVersion()) > 128 {
		return nil, arc.InvalidArgument("price_version", "required")
	}
	purchase, err := s.service.CreatePurchase(ctx, input.actor, commerce.PurchaseRequest{CommandID: input.command,
		PurchaseID: purchaseID, OfferID: offerID, PriceVersion: request.GetPriceVersion(), Region: request.GetRegion(), CommandPayload: input.bytes})
	if err != nil {
		return nil, err
	}
	return &publicapiv1.CommerceServiceCreatePurchaseIntentValue{Purchase: wirePurchase(purchase)}, nil
}

func (s commerceRPC) createCheckout(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceCreateCheckoutAttemptRequest) (*publicapiv1.CommerceServiceCreateCheckoutAttemptValue, error) {
	purchaseID, err := commerceID(request.PurchaseIntentId, "purchase_intent_id")
	if err != nil {
		return nil, err
	}
	checkoutID, err := commerceID(request.CheckoutAttemptId, "checkout_attempt_id")
	if err != nil {
		return nil, err
	}
	if request.GetReturnRoute() != billingReturnPath {
		return nil, arc.InvalidArgument("return_route", "not_admitted")
	}
	checkout, err := s.service.CreateCheckout(ctx, input.actor, commerce.CheckoutAttemptRequest{CommandID: input.command,
		PurchaseID: purchaseID, CheckoutID: checkoutID, ReturnPath: billingReturnPath, CommandPayload: input.bytes})
	if err != nil {
		return nil, err
	}
	if checkout.URL == "" {
		switch checkout.State {
		case "completed", "expired":
			return nil, arc.InvalidState("checkout", checkout.State)
		default:
			// The published checkout value requires a URL. A pending provider
			// result remains an unknown effect, which the purchase read can show.
			return nil, arc.Internal()
		}
	}
	return &publicapiv1.CommerceServiceCreateCheckoutAttemptValue{Checkout: &publicapiv1.CheckoutView{
		CheckoutAttemptId: wireCommerceID(checkout.ID), PurchaseIntentId: wireCommerceID(checkout.PurchaseID),
		Url: proto.String(checkout.URL), ExpiresAt: arc.Instant(checkout.ExpiresAt),
	}}, nil
}

func (s commerceRPC) getPurchase(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceGetPurchaseStateRequest) (*publicapiv1.CommerceServiceGetPurchaseStateValue, error) {
	id, err := commerceID(request.PurchaseIntentId, "purchase_intent_id")
	if err != nil {
		return nil, err
	}
	purchase, err := s.service.GetPurchase(ctx, input.actor, id)
	if err != nil {
		return nil, err
	}
	return &publicapiv1.CommerceServiceGetPurchaseStateValue{Purchase: wirePurchase(purchase)}, nil
}

func wirePurchase(purchase commerce.Purchase) *publicapiv1.PurchaseView {
	return &publicapiv1.PurchaseView{PurchaseIntentId: wireCommerceID(purchase.ID), OfferId: wireCommerceID(purchase.OfferID),
		State: proto.String(purchase.State)}
}

func (s commerceRPC) getSubscription(ctx context.Context, input commerceInput, _ *publicapiv1.CommerceServiceGetSubscriptionRequest) (*publicapiv1.CommerceServiceGetSubscriptionValue, error) {
	result, err := s.service.GetSubscription(ctx, input.actor)
	if err != nil {
		return nil, err
	}
	subscription, err := wireSubscription(result)
	if err != nil {
		return nil, err
	}
	return &publicapiv1.CommerceServiceGetSubscriptionValue{Subscription: subscription}, nil
}

func (s commerceRPC) cancelSubscription(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceCancelSubscriptionRequest) (*publicapiv1.CommerceServiceCancelSubscriptionValue, error) {
	subscription, err := s.setRenewal(ctx, input, request.SubscriptionId, request.Meta.GetExpectedRev(), false)
	if err != nil {
		return nil, err
	}
	return &publicapiv1.CommerceServiceCancelSubscriptionValue{Subscription: subscription}, nil
}

func (s commerceRPC) reactivateSubscription(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceReactivateSubscriptionRequest) (*publicapiv1.CommerceServiceReactivateSubscriptionValue, error) {
	subscription, err := s.setRenewal(ctx, input, request.SubscriptionId, request.Meta.GetExpectedRev(), true)
	if err != nil {
		return nil, err
	}
	return &publicapiv1.CommerceServiceReactivateSubscriptionValue{Subscription: subscription}, nil
}

func (s commerceRPC) setRenewal(ctx context.Context, input commerceInput, id *foundationv1.Id, revision *foundationv1.Revision, autoRenew bool) (*publicapiv1.SubscriptionView, error) {
	subscriptionID, err := commerceID(id, "subscription_id")
	if err != nil {
		return nil, err
	}
	if revision.GetValue() <= 0 || len(revision.ProtoReflect().GetUnknown()) != 0 {
		return nil, arc.InvalidArgument("meta.expected_rev", "required")
	}
	result, err := s.service.SetRenewal(ctx, input.actor, commerce.RenewalRequest{CommandID: input.command, SubscriptionID: subscriptionID,
		AutoRenew: autoRenew, ExpectedRevision: revision.GetValue(), CommandPayload: input.bytes})
	if err != nil {
		return nil, err
	}
	if result.AutoRenew != autoRenew {
		return nil, arc.Internal()
	}
	return wireSubscription(result)
}

func wireSubscription(subscription commerce.SubscriptionView) (*publicapiv1.SubscriptionView, error) {
	var state publicapiv1.SubscriptionState
	switch subscription.State {
	case "pending":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_PENDING
	case "active":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_ACTIVE
	case "cancel_at_term_end":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_CANCEL_SCHEDULED
	case "payment_grace":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_GRACE
	case "expired":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_ENDED
	case "revoked":
		state = publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_SUSPENDED
	case "provider_unknown":
		return nil, arc.InvalidState("subscription", "provider_unknown")
	default:
		return nil, arc.Internal()
	}
	if subscription.PeriodStart.IsZero() || !subscription.PeriodStart.Before(subscription.PeriodEnd) {
		return nil, arc.InvalidState("subscription", "period_unverified")
	}
	return &publicapiv1.SubscriptionView{SubscriptionId: wireCommerceID(subscription.ID), State: state.Enum(),
		CurrentPeriod: &foundationv1.TimeRangeUtc{From: arc.Instant(subscription.PeriodStart), Until: arc.Instant(subscription.PeriodEnd)},
		CancelAtPeriodEnd: proto.Bool(!subscription.AutoRenew && (state == publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_ACTIVE ||
			state == publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_CANCEL_SCHEDULED || state == publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_GRACE)),
		Revision: wireCommerceRevision(subscription.Revision),
	}, nil
}

func (s commerceRPC) listBilling(ctx context.Context, input commerceInput, request *publicapiv1.CommerceServiceListBillingHistoryRequest) (*publicapiv1.CommerceServiceListBillingHistoryValue, error) {
	period := request.Period
	if period == nil || len(period.ProtoReflect().GetUnknown()) != 0 {
		return nil, arc.InvalidArgument("period", "required")
	}
	from, fromOK := commerceInstant(period.From)
	until, untilOK := commerceInstant(period.Until)
	if !fromOK || !untilOK || !from.Before(until) {
		return nil, arc.InvalidArgument("period", "billing_bounds")
	}
	paging := request.Page
	if paging == nil || len(paging.ProtoReflect().GetUnknown()) != 0 {
		return nil, arc.InvalidArgument("page", "required")
	}
	if len(paging.GetCursor()) > 128 {
		return nil, arc.InvalidCursor()
	}
	parsed, refusal := page.Parse(billingListing, paging.GetCursor(), paging.GetLimit(), paging.Limit != nil)
	if refusal != nil {
		return nil, refusal
	}
	query := commerce.BillingQuery{From: from, Until: until, Limit: parsed.Limit}
	if parsed.After != nil {
		query.Before, query.BeforeID = parsed.After.At, parsed.After.ID
	}
	result, err := s.service.ListBilling(ctx, input.actor, query)
	if err != nil {
		return nil, err
	}
	reply := &publicapiv1.CommerceServiceListBillingHistoryValue{Page: &foundationv1.PageState{HasMore: proto.Bool(result.HasMore)}}
	for _, entry := range result.Items {
		amount, ok := commerceMoney(entry.AmountMinor, entry.Currency)
		if !ok {
			return nil, arc.Internal()
		}
		reply.Items = append(reply.Items, &publicapiv1.BillingItem{ItemId: wireCommerceID(entry.ID), Kind: proto.String(entry.Kind),
			State: proto.String("settled"), Amount: amount, Currency: proto.String(entry.Currency), OccurredAt: arc.Instant(entry.OccurredAt)})
	}
	if result.HasMore {
		last := result.Items[len(result.Items)-1]
		reply.Page.NextCursor = proto.String(page.Encode(billingListing, page.Cursor{At: last.OccurredAt, ID: last.ID}))
	}
	return reply, nil
}

func commerceInstant(instant *foundationv1.Instant) (time.Time, bool) {
	if instant == nil || instant.UnixSeconds == nil || instant.GetUnixSeconds() < -62135596800 ||
		instant.GetUnixSeconds() > 253402300799 || instant.GetNanos() >= 1_000_000_000 || len(instant.ProtoReflect().GetUnknown()) != 0 {
		return time.Time{}, false
	}
	value := time.Unix(instant.GetUnixSeconds(), int64(instant.GetNanos())).UTC()
	// Preserve the half-open interval over the store's microsecond timestamps.
	rounded := value.Truncate(time.Microsecond)
	if rounded.Before(value) {
		rounded = rounded.Add(time.Microsecond)
	}
	return rounded, true
}

func getCatalogueReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceGetCatalogueValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceGetCatalogueResponse {
	response := &publicapiv1.CommerceServiceGetCatalogueResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceGetCatalogueResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceGetCatalogueResponse_Value{Value: value}
	}
	return response
}

func createPurchaseReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceCreatePurchaseIntentValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceCreatePurchaseIntentResponse {
	response := &publicapiv1.CommerceServiceCreatePurchaseIntentResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceCreatePurchaseIntentResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceCreatePurchaseIntentResponse_Value{Value: value}
	}
	return response
}

func createCheckoutReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceCreateCheckoutAttemptValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceCreateCheckoutAttemptResponse {
	response := &publicapiv1.CommerceServiceCreateCheckoutAttemptResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceCreateCheckoutAttemptResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceCreateCheckoutAttemptResponse_Value{Value: value}
	}
	return response
}

func getPurchaseReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceGetPurchaseStateValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceGetPurchaseStateResponse {
	response := &publicapiv1.CommerceServiceGetPurchaseStateResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceGetPurchaseStateResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceGetPurchaseStateResponse_Value{Value: value}
	}
	return response
}

func getSubscriptionReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceGetSubscriptionValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceGetSubscriptionResponse {
	response := &publicapiv1.CommerceServiceGetSubscriptionResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceGetSubscriptionResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceGetSubscriptionResponse_Value{Value: value}
	}
	return response
}

func cancelSubscriptionReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceCancelSubscriptionValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceCancelSubscriptionResponse {
	response := &publicapiv1.CommerceServiceCancelSubscriptionResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceCancelSubscriptionResponse_Error{Error: failure}
	} else {
		meta.ResultRev = value.Subscription.Revision
		response.Outcome = &publicapiv1.CommerceServiceCancelSubscriptionResponse_Value{Value: value}
	}
	return response
}

func reactivateSubscriptionReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceReactivateSubscriptionValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceReactivateSubscriptionResponse {
	response := &publicapiv1.CommerceServiceReactivateSubscriptionResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceReactivateSubscriptionResponse_Error{Error: failure}
	} else {
		meta.ResultRev = value.Subscription.Revision
		response.Outcome = &publicapiv1.CommerceServiceReactivateSubscriptionResponse_Value{Value: value}
	}
	return response
}

func listBillingReply(meta *foundationv1.ResponseMeta, value *publicapiv1.CommerceServiceListBillingHistoryValue, failure *foundationv1.ArcError) *publicapiv1.CommerceServiceListBillingHistoryResponse {
	response := &publicapiv1.CommerceServiceListBillingHistoryResponse{Meta: meta}
	if failure != nil {
		response.Outcome = &publicapiv1.CommerceServiceListBillingHistoryResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.CommerceServiceListBillingHistoryResponse_Value{Value: value}
	}
	return response
}
