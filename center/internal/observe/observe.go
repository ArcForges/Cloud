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
}

// NewMetrics is an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{requests: map[requestKey]uint64{}, latencies: map[string]*histogram{}, refusals: map[refusalKey]uint64{},
		identity: map[eventKey]uint64{}}
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
// (rotated, refused, reused), rate-limit refusals by bucket kind, bootstrap outcomes and e-mail deliveries. Both labels are closed
// values chosen by the code, never request content.
func (m *Metrics) ObserveIdentity(event, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identity[eventKey{event, outcome}]++
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
	_, err := io.WriteString(writer, text.String())
	return err
}

// Summary is the request counts by method and outcome, for the periodic metrics log line.
func (m *Metrics) Summary() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	summary := make(map[string]uint64, len(m.requests)+len(m.refusals)+len(m.identity))
	for key, count := range m.requests {
		summary[key.method+" "+key.code] = count
	}
	for key, count := range m.refusals {
		summary["refused "+key.code+" "+key.category] += count
	}
	for key, count := range m.identity {
		summary["identity "+key.event+" "+key.outcome] += count
	}
	return summary
}

func formatBound(bound float64) string { return fmt.Sprintf("%g", bound) }
