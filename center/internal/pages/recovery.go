// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"strconv"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identityapi"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
)

func (e *exchange) recoveryPage() { e.serve("recovery", pageData{Title: "Recover your account"}) }

func parseRecoveryBegin(data []byte) (identity.RecoveryBegin, *arc.Refusal) {
	root, refusal := parseObject(data, "", "method", "email", "installation")
	if refusal != nil {
		return identity.RecoveryBegin{}, refusal
	}
	if _, refusal = root.requiredText("method", textRule{enum: []string{"emailCode"}}); refusal != nil {
		return identity.RecoveryBegin{}, refusal
	}
	email, refusal := root.requiredText("email", textRule{min: 3, max: 320, pattern: loginHintPattern})
	if refusal != nil {
		return identity.RecoveryBegin{}, refusal
	}
	claim, refusal := parseClaim(root)
	return identity.RecoveryBegin{Email: email, Claim: claim, HasClaim: true, Browser: true}, refusal
}

func parseRecoveryComplete(data []byte) (identity.RecoveryComplete, *arc.Refusal) {
	root, refusal := parseObject(data, "", "flowId", "commandId", "proof", "replacement")
	if refusal != nil {
		return identity.RecoveryComplete{}, refusal
	}
	result := identity.RecoveryComplete{Browser: true}
	if result.FlowID, refusal = root.requiredUUID("flowId"); refusal != nil {
		return result, refusal
	}
	if result.CommandID, refusal = root.requiredUUID("commandId"); refusal != nil {
		return result, refusal
	}
	proof, refusal := root.requiredChild("proof", "emailCode")
	if refusal != nil {
		return result, refusal
	}
	if result.EmailCode, refusal = proof.requiredText("emailCode", textRule{min: 1, max: 128}); refusal != nil {
		return result, refusal
	}
	replacement, refusal := root.requiredChild("replacement", "passkey")
	if refusal != nil {
		return result, refusal
	}
	result.Creation, refusal = readCreation(replacement, "passkey")
	return result, refusal
}

func (e *exchange) beginRecovery() {
	if _, ok := e.guard(false, ""); !ok {
		return
	}
	body, refusal := parseRecoveryBegin(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if _, ok := e.authorized(publicapiv1connect.IdentityServiceBeginRecoveryProcedure, nil, e.body); !ok {
		return
	}
	value, err := e.h.options.Identity.BeginRecovery(e.r.Context(), e.request(), body)
	if err != nil {
		e.fail(err)
		return
	}
	e.writeJSON(challengeOf(identityapi.ChallengeView(value, e.h.options.Identity.RelyingParty().RPID())), "")
}

func (e *exchange) completeRecovery() {
	if _, ok := e.guard(false, ""); !ok {
		return
	}
	body, refusal := parseRecoveryComplete(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if _, ok := e.authorized(publicapiv1connect.IdentityServiceCompleteRecoveryProcedure, nil, e.body); !ok {
		return
	}
	value, err := e.h.options.Identity.CompleteRecovery(e.r.Context(), e.request(), body)
	if err != nil {
		e.fail(err)
		return
	}
	// Recovery returns metadata, never an old or privileged session.
	e.writeJSON(receiptReply{CommandID: uuidText(body.CommandID), ResultRevision: strconv.FormatInt(value.Revision, 10), Effect: "happened"}, "")
}
