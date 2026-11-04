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
}

// FleetOutcomes is the closed label set of the fleet surface's events (AF-CTR-04, CR-02): the refresh of a node session (rotated,
// a spent token's reuse, refused, rate limited), a report of node info (changed, unchanged, rate limited), an enrollment (first or
// re-enrolled, and its refusals: the node ID live in another account, the key held live, the key retired, the node cap, an approval
// that lapsed), a node's sign-out, and the browser sign-in (AF-CTR-04 E1b): a Begin (started, refused, rate limited), a review
// (recorded, shown without a record, refused), a decision (approved, its code reissued, denied, refused, rate limited) and a Complete
// (completed, refused, a correct code presented again, a failed verifier or key proof, an approval that lapsed, rate limited).
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
	}
}

// Unlisted is the label pair a fleet event outside FleetOutcomes is counted under.
const Unlisted = "unlisted"

// NewMetrics is an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{requests: map[requestKey]uint64{}, latencies: map[string]*histogram{}, refusals: map[refusalKey]uint64{},
		identity: map[eventKey]uint64{}, fleet: map[eventKey]uint64{}}
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
	_, err := io.WriteString(writer, text.String())
	return err
}

// Summary is the request counts by method and outcome, for the periodic metrics log line.
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
	return summary
}

func formatBound(bound float64) string { return fmt.Sprintf("%g", bound) }
