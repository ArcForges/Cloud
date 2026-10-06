# Versioned Commerce catalogue (COM.02)

Commerce owns the persistent offer and immutable price-version read model through
five named D1 plans. Module registration exposes primitive state, historical/effective
query and trusted configuration-publication ports. It opens no ingress route and
installs no permissive approval source. Resolving publication requires the actual
`ICataloguePublicationAuthority` supplied by POL.02; reads require the existing
signed executor factory supplied by host composition.

Configuration approves the exact bytes produced by `CatalogueCanonical.Create`.
The publication adapter verifies the configuration/offer IDs, canonical SHA-256,
publisher, distinct proposer and approver and distinct proposal/approval IDs, and
approval/effective times before persistence. The authoritative source must verify
the actual accepted activation and publisher permission, including accepted
historical revisions needed for recovery replay. A caller-supplied Boolean is
never evidence. New purchases still require the current active configuration and
approved provider mapping; catalogue reads alone authorize no checkout.

Each publication atomically compares the expected offer revision, inserts a new
price, stores its replay receipt and appends the canonical change archive. There
is no catalogue outbox consumer and this plan declares zero outbox events. The
generic executor checks the receipt before a repeated write. Unknown responses
and unavailable transport are retried at most twice with the same command,
fingerprint and timestamps; stable refusals are returned without retry. Cancellation
propagates. A cancelled or lost response is not proof that a write rolled back.

Version and effective start strictly increase; gaps are allowed for obsolete
configuration activations. The newest started price supersedes earlier rows even
when the earlier row has no end. Ends are exclusive; an expired newest price does
not resurrect an older one. Old price rows are never updated, including their
ends. Kind, scope and term profile cannot change for an existing offer; a new
offer identity is required for a different structural product. Display name and
active state can change at an effective activation, but future changes to those
unversioned display fields are refused until their start. Unchanged display
metadata permits staging a future price. Approval must precede its effective
start; late materialization and replay remain valid.

Exact historical lookup retains the original amount, currency, tax category,
configuration revision and structural profile. Current name/active state are
display metadata and must not be interpreted as original order authorization.
Existing orders and captured payments retain their own original amount/currency
and price reference. There is no default currency, compiled commercial figure or
provider-specific identifier format. Active V1 products are subscription, pass
and credit; storage add-ons can be configured inactive until their separate launch.

Component tests run the actual application, persistent store, receipt adapter,
Worker plan executor and every numbered migration against SQLite. Fakes are only
the unavailable Configuration authority and injected unavailable transport/unknown
responses. This proves component persistence, guard rollback, concurrency, replay,
approval refusal, cancellation, effective boundaries and historical-order
preservation. SQLite is not Cloudflare D1; it proves neither real deployment nor
provider checkout. POL.02 owns real source integration, CLOUD.21 owns production
signed-executor composition, and COM.03 owns new-purchase approval/provider
mapping. Whole-series commerce acceptance remains a separate check.
