// SPDX-License-Identifier: AGPL-3.0-only

// Package observe is the center's structured logging and its request metrics. Logs are JSON lines (log/slog) that carry the
// correlation id of a call and never a secret, a command line, a request or response body, a header value, output or file
// content: a request line names only the registered method (or a fixed word), the status, the duration and the correlation
// identity. Metrics are counters and latency histograms per method and outcome and refusal counts per ArcError category; they
// are exposed in the Prometheus text format on the admin listener and summarized in a periodic log line, so the hosted
// Container needs no public route for them.
package observe

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// NewLogger is the center's JSON logger.
func NewLogger(writer io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})).With("service", "arcforges-center")
}

// LatencyBuckets are the upper bounds of the request latency histogram, in seconds.
var LatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type requestKey struct{ method, code string }

type histogram struct {
	buckets []uint64
	count   uint64
	sum     float64
}

type refusalKey struct{ code, category string }

type eventKey struct{ event, outcome string }

// Metrics is the center's request metrics. Labels are closed values: a registered method path or a fixed word, a gRPC code
// name or an HTTP status, a registry code and an ArcError category.
type Metrics struct {
	mu        sync.Mutex
	requests  map[requestKey]uint64
	latencies map[string]*histogram
	refusals  map[refusalKey]uint64
	identity  map[eventKey]uint64
	fleet     map[eventKey]uint64
	mobile    map[eventKey]uint64
	channel   map[eventKey]uint64
	// connected is the node channel's accepted connections (a gauge); superseded is 1 while this revision's definitions version is
	// not the deploy's current one (E0 C-N2), set by the server at every scrape.
	connected  int
	inFlight   int
	superseded int
}

// FleetOutcomes is the closed label set of the fleet surface's events (AF-CTR-04, CR-02): the refresh of a node session (rotated,
// a spent token's reuse, refused, rate limited), a report of node info (changed, unchanged, rate limited), an enrollment (first or
// re-enrolled, and its refusals: the node ID live in another account, the key held live, the key retired, the node cap, an approval
// that lapsed), a node's sign-out, and the browser sign-in (AF-CTR-04 E1b): a Begin (started, refused, rate limited), a review
// (recorded, shown without a record, refused), a decision (approved, its code reissued, denied, refused, rate limited) and a Complete
// (completed, refused, a correct code presented again, a failed verifier or key proof, an approval that lapsed, rate limited), and
// the device-code sign-in (AF-CTR-04 E2): a Start (started, refused, rate limited), a poll (each state value it answers, delivered
// credentials, a reuse, a lapse, an unknown code, a failed key proof, refused, rate limited), a lookup (shown, refused, rate limited),
// a decision (approved, denied, refused, rate limited) and every user-code entry that keeps its reservation, by kind (an unknown or
// foreign code, an expired code, a code in another state, a decision without the caller's review, a live code's sixth lookup), and an
// account's rename of a node (AF-CTR-05 E2a).
// ObserveFleet counts only these pairs; any other pair is counted as unlisted, and the fleet surface's integration harness (fleetapi)
// fails every test after which the composed center counted an unlisted pair.
func FleetOutcomes() map[string][]string {
	return map[string][]string{
		"refresh":  {"rotated", "reused", "refused", "rate_limited"},
		"enroll":   {"first", "reenrolled", "node_conflict", "key_registered", "key_retired", "quota", "lapsed"},
		"report":   {"changed", "unchanged", "rate_limited"},
		"sign_out": {"signed_out"},
		"begin":    {"started", "refused", "rate_limited"},
		"review":   {"reviewed", "shown", "refused"},
		"approve":  {"approved", "reissued", "denied", "refused", "rate_limited"},
		"complete": {"completed", "refused", "reused", "proof_failed", "lapsed", "rate_limited"},
		"start":    {"started", "refused", "rate_limited"},
		"poll": {"pending", "slow_down", "delivered", "denied", "expired", "reused", "lapsed", "not_found", "proof_failed", "refused",
			"rate_limited"},
		"lookup":        {"shown", "refused", "rate_limited"},
		"device_decide": {"approved", "denied", "refused", "rate_limited"},
		"entry":         {"unknown", "expired", "state", "unreviewed", "lookups", "tail"},
		"rename":        {"renamed"},
	}
}

// MobileOutcomes is the closed label set of the mobile surface's events (AF-CTR-04 part M, M-11): a begin (started, refused, rate
// limited), a review (reviewed, shown, refused, rate limited: a review that shows a foreign or revoked installation is counted), a decision (approved, a code reissued, denied, refused, rate limited) and a token
// request (completed, refused, a reuse, a failed verifier or binding, a lapsed approval, rate limited). ObserveMobile counts only these
// pairs; any other pair is counted as unlisted.
func MobileOutcomes() map[string][]string {
	return map[string][]string{
		"begin":   {"started", "refused", "rate_limited"},
		"review":  {"reviewed", "shown", "refused", "rate_limited"},
		"approve": {"approved", "reissued", "denied", "refused", "rate_limited"},
		"token":   {"completed", "refused", "reused", "verifier_failed", "lapsed", "rate_limited"},
	}
}

// ChannelOutcomes is the closed label set of the node channel's events (AF-CTR-05 E1a, Plan C.10): upgrades opened, refused before
// the upgrade by stage, hellos by outcome, closes by close code (or normal, abnormal), heartbeat deadlines missed, violations by
// reason, token refreshes (rebound, unchanged, over the refresh rate), lapse checks that closed or could not decide, and the hub
// lease's changes and failed renewals. ObserveChannel counts only these
// pairs; any other pair is counted as unlisted.
func ChannelOutcomes() map[string][]string {
	return map[string][]string{
		"opened":    {"upgraded"},
		"refused":   {"request", "lease", "credential", "authorization", "node", "connections", "handshake"},
		"hello":     {"accepted", "malformed", "signature", "mismatch", "deadline", "no_signing_key", "fenced", "node_gone", "unrecorded"},
		"closed":    {"4401", "4403", "4408", "4409", "4413", "4429", "4500", "4503", "normal", "abnormal"},
		"heartbeat": {"missed"},
		"violation": {"too_large", "rate", "write_timeout", "text_frame", "unreadable_frame", "before_hello", "unexpected_frame", "hello_without_nonce",
			"hello_malformed", "hello_signature", "hello_mismatch", "result_malformed", "result_signature", "result_other_call", "result_mismatch",
			"nonce_request_malformed"},
		// AF-CTR-05 E1b: routed calls (sent, the outcome of a verified result, a late result dropped, the refusals before sending, and
		// the reasons of node_unreachable), relay nonces and relay assertions (verified, or the closed reason of the refusal); AF-CTR-05 E2a: a
		// result for a call whose late entry was already forgotten, verified and dropped (forgotten).
		"call": {"sent", "executed", "refused_by_policy", "refused_verification", "expired", "late", "forgotten", "offline", "no_key", "center_bound",
			"node_bound", "queue_full", "channel_closed", "deadline_passed", "result_unverifiable"},
		"relay_nonce": {"issued", "spent", "unknown"},
		"assertion":   {"verified", "missing", "signature_invalid", "credential_mismatch", "expired", "nonce_reused", "request_mismatch"},
		"token":       {"rebound", "unchanged", "rate"},
		"lapse":       {"closed", "undecided"},
		"lease":       {"acquired", "held_elsewhere", "renewal_failed", "lost", "released", "swept", "sweep_failed"},
		// AF-CTR-05 E2b: the routed API (an attempt admitted, a duplicate joined, a call to an offline node, a settlement written or
		// lost after its retries, a replayed outcome with another digest, a long poll over the center's bound).
		"routed": {"accepted", "joined", "offline", "settled", "settle_lost", "replay_differs", "long_polls"},
	}
}

// Unlisted is the label pair a fleet event outside FleetOutcomes is counted under.
const Unlisted = "unlisted"

// NewMetrics is an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{requests: map[requestKey]uint64{}, latencies: map[string]*histogram{}, refusals: map[refusalKey]uint64{},
		identity: map[eventKey]uint64{}, fleet: map[eventKey]uint64{}, mobile: map[eventKey]uint64{}, channel: map[eventKey]uint64{}}
}

// ObserveRequest counts one finished request.
func (m *Metrics) ObserveRequest(method, code string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{method, code}]++
	entry := m.latencies[method]
	if entry == nil {
		entry = &histogram{buckets: make([]uint64, len(LatencyBuckets))}
		m.latencies[method] = entry
	}
	seconds := duration.Seconds()
	for index, bound := range LatencyBuckets {
		if seconds <= bound {
			entry.buckets[index]++
		}
	}
	entry.count++
	entry.sum += seconds
}

// ObserveRefusal counts one refusal of the ingress pipeline by its registry code and ArcError category.
func (m *Metrics) ObserveRefusal(code, category string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refusals[refusalKey{code, category}]++
}

// ObserveIdentity counts one outcome of the identity surface (AF-CTR-03): sign-in stages by method and outcome, refreshes
// (rotated, refused, reused), rate-limit refusals by bucket kind, bootstrap outcomes, e-mail code requests and deliveries, step-up
// stages (step_up_begin by method; step_up_complete proved, refused or upgraded) and passkey registration (registration_begin;
// registration_complete succeeded or refused). Both labels are closed values chosen by the code, never request content.
func (m *Metrics) ObserveIdentity(event, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identity[eventKey{event, outcome}]++
}

// ObserveFleet counts one outcome of the fleet surface; both labels are closed values of FleetOutcomes chosen by the code.
func (m *Metrics) ObserveFleet(event, outcome string) {
	key := eventKey{Unlisted, Unlisted}
	for _, listed := range FleetOutcomes()[event] {
		if listed == outcome {
			key = eventKey{event, outcome}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fleet[key]++
}

// ObserveMobile counts one outcome of the mobile surface; both labels are closed values of MobileOutcomes chosen by the code.
func (m *Metrics) ObserveMobile(event, outcome string) {
	key := eventKey{Unlisted, Unlisted}
	for _, listed := range MobileOutcomes()[event] {
		if listed == outcome {
			key = eventKey{event, outcome}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mobile[key]++
}

// ObserveChannel counts one outcome of the node channel; both labels are closed values of ChannelOutcomes chosen by the code.
func (m *Metrics) ObserveChannel(event, outcome string) {
	key := eventKey{Unlisted, Unlisted}
	for _, listed := range ChannelOutcomes()[event] {
		if listed == outcome {
			key = eventKey{event, outcome}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channel[key]++
}

// ChannelCount is how often the node channel counted a pair (tests read it).
func (m *Metrics) ChannelCount(event, outcome string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.channel[eventKey{event, outcome}]
}

// SetChannelConnected sets the gauge of the node channel's accepted connections.
func (m *Metrics) SetChannelConnected(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = count
}

// SetChannelInFlight sets the gauge of the routed calls this process waits for (AF-CTR-05 E1b).
func (m *Metrics) SetChannelInFlight(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight = count
}

// SetDefinitionsSuperseded sets the gauge of a revision whose definitions version is not the deploy's current one (E0 C-N2).
func (m *Metrics) SetDefinitionsSuperseded(superseded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.superseded = 0
	if superseded {
		m.superseded = 1
	}
}

// MobileCount is how often the mobile surface counted a pair (tests read it; an unlisted pair is counted as Unlisted, Unlisted).
func (m *Metrics) MobileCount(event, outcome string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mobile[eventKey{event, outcome}]
}

// WritePrometheus writes the metrics in the Prometheus text exposition format (version 0.0.4).
func (m *Metrics) WritePrometheus(writer io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var text strings.Builder
	text.WriteString("# HELP arcforges_center_requests_total Requests finished, by method and outcome code.\n")
	text.WriteString("# TYPE arcforges_center_requests_total counter\n")
	requests := make([]requestKey, 0, len(m.requests))
	for key := range m.requests {
		requests = append(requests, key)
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].method+"\x00"+requests[i].code < requests[j].method+"\x00"+requests[j].code
	})
	for _, key := range requests {
		fmt.Fprintf(&text, "arcforges_center_requests_total{method=%q,code=%q} %d\n", key.method, key.code, m.requests[key])
	}
	text.WriteString("# HELP arcforges_center_request_duration_seconds Request latency, by method.\n")
	text.WriteString("# TYPE arcforges_center_request_duration_seconds histogram\n")
	methods := make([]string, 0, len(m.latencies))
	for method := range m.latencies {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, method := range methods {
		entry := m.latencies[method]
		for index, bound := range LatencyBuckets {
			fmt.Fprintf(&text, "arcforges_center_request_duration_seconds_bucket{method=%q,le=%q} %d\n", method, formatBound(bound), entry.buckets[index])
		}
		fmt.Fprintf(&text, "arcforges_center_request_duration_seconds_bucket{method=%q,le=\"+Inf\"} %d\n", method, entry.count)
		fmt.Fprintf(&text, "arcforges_center_request_duration_seconds_sum{method=%q} %g\n", method, entry.sum)
		fmt.Fprintf(&text, "arcforges_center_request_duration_seconds_count{method=%q} %d\n", method, entry.count)
	}
	text.WriteString("# HELP arcforges_center_refusals_total Ingress refusals, by registry code and ArcError category.\n")
	text.WriteString("# TYPE arcforges_center_refusals_total counter\n")
	refusals := make([]refusalKey, 0, len(m.refusals))
	for key := range m.refusals {
		refusals = append(refusals, key)
	}
	sort.Slice(refusals, func(i, j int) bool {
		return refusals[i].code+"\x00"+refusals[i].category < refusals[j].code+"\x00"+refusals[j].category
	})
	for _, key := range refusals {
		fmt.Fprintf(&text, "arcforges_center_refusals_total{code=%q,category=%q} %d\n", key.code, key.category, m.refusals[key])
	}
	text.WriteString("# HELP arcforges_center_identity_events_total Identity surface outcomes, by event and outcome.\n")
	text.WriteString("# TYPE arcforges_center_identity_events_total counter\n")
	events := make([]eventKey, 0, len(m.identity))
	for key := range m.identity {
		events = append(events, key)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].event+"\x00"+events[i].outcome < events[j].event+"\x00"+events[j].outcome
	})
	for _, key := range events {
		fmt.Fprintf(&text, "arcforges_center_identity_events_total{event=%q,outcome=%q} %d\n", key.event, key.outcome, m.identity[key])
	}
	text.WriteString("# HELP arcforges_center_fleet_events_total Fleet surface outcomes, by event and outcome.\n")
	text.WriteString("# TYPE arcforges_center_fleet_events_total counter\n")
	fleet := make([]eventKey, 0, len(m.fleet))
	for key := range m.fleet {
		fleet = append(fleet, key)
	}
	sort.Slice(fleet, func(i, j int) bool {
		return fleet[i].event+"\x00"+fleet[i].outcome < fleet[j].event+"\x00"+fleet[j].outcome
	})
	for _, key := range fleet {
		fmt.Fprintf(&text, "arcforges_center_fleet_events_total{event=%q,outcome=%q} %d\n", key.event, key.outcome, m.fleet[key])
	}
	text.WriteString("# HELP arcforges_center_mobile_events_total Mobile surface outcomes, by event and outcome.\n")
	text.WriteString("# TYPE arcforges_center_mobile_events_total counter\n")
	mobile := make([]eventKey, 0, len(m.mobile))
	for key := range m.mobile {
		mobile = append(mobile, key)
	}
	sort.Slice(mobile, func(i, j int) bool {
		return mobile[i].event+"\x00"+mobile[i].outcome < mobile[j].event+"\x00"+mobile[j].outcome
	})
	for _, key := range mobile {
		fmt.Fprintf(&text, "arcforges_center_mobile_events_total{event=%q,outcome=%q} %d\n", key.event, key.outcome, m.mobile[key])
	}
	text.WriteString("# HELP arcforges_center_channel_events_total Node channel outcomes, by event and outcome.\n")
	text.WriteString("# TYPE arcforges_center_channel_events_total counter\n")
	channel := make([]eventKey, 0, len(m.channel))
	for key := range m.channel {
		channel = append(channel, key)
	}
	sort.Slice(channel, func(i, j int) bool {
		return channel[i].event+"\x00"+channel[i].outcome < channel[j].event+"\x00"+channel[j].outcome
	})
	for _, key := range channel {
		fmt.Fprintf(&text, "arcforges_center_channel_events_total{event=%q,outcome=%q} %d\n", key.event, key.outcome, m.channel[key])
	}
	text.WriteString("# HELP arcforges_center_channel_connected_nodes Node channel connections accepted in this process.\n")
	text.WriteString("# TYPE arcforges_center_channel_connected_nodes gauge\n")
	fmt.Fprintf(&text, "arcforges_center_channel_connected_nodes %d\n", m.connected)
	text.WriteString("# HELP arcforges_center_channel_calls_in_flight Routed calls this process waits for.\n")
	text.WriteString("# TYPE arcforges_center_channel_calls_in_flight gauge\n")
	fmt.Fprintf(&text, "arcforges_center_channel_calls_in_flight %d\n", m.inFlight)
	text.WriteString("# HELP arcforges_center_definitions_superseded 1 while this revision's definitions version is not the deploy's current one.\n")
	text.WriteString("# TYPE arcforges_center_definitions_superseded gauge\n")
	fmt.Fprintf(&text, "arcforges_center_definitions_superseded %d\n", m.superseded)
	_, err := io.WriteString(writer, text.String())
	return err
}

// Summary keys of the two gauges (AF-CTR-05 E1a, review B B-2): the hosted Container has no admin listener, so the periodic metrics
// log line is the operator's only view of them.
const (
	SummaryDefinitionsSuperseded = "definitions superseded"
	SummaryChannelConnected      = "channel connected_nodes"
)

// Summary is the request counts by method and outcome, the surfaces' event counts and the two gauges, for the periodic metrics log
// line.
func (m *Metrics) Summary() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	summary := make(map[string]uint64, len(m.requests)+len(m.refusals)+len(m.identity)+len(m.fleet))
	for key, count := range m.requests {
		summary[key.method+" "+key.code] = count
	}
	for key, count := range m.refusals {
		summary["refused "+key.code+" "+key.category] += count
	}
	for key, count := range m.identity {
		summary["identity "+key.event+" "+key.outcome] += count
	}
	for key, count := range m.fleet {
		summary["fleet "+key.event+" "+key.outcome] += count
	}
	for key, count := range m.mobile {
		summary["mobile "+key.event+" "+key.outcome] += count
	}
	for key, count := range m.channel {
		summary["channel "+key.event+" "+key.outcome] += count
	}
	summary[SummaryDefinitionsSuperseded] = uint64(m.superseded)
	summary[SummaryChannelConnected] = uint64(max(m.connected, 0))
	return summary
}

func formatBound(bound float64) string { return fmt.Sprintf("%g", bound) }
