// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"fmt"
	"io"
	"strings"
)

// Capacity measures active reservations and the enforced process limit.
type Capacity struct {
	Active int64 `json:"active"`
	Limit  int64 `json:"limit"`
}

type SourceState string

const (
	SourceDisabled    SourceState = "disabled"
	SourceUnavailable SourceState = "unavailable"
	SourceReady       SourceState = "ready"
)

// ObserveManagementWatch is called from the watch reservation pool while
// its lock is held, so competing take and release events retain their order.
func (m *Metrics) ObserveManagementWatch(active, limit int, refusal string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.managementWatch = Capacity{Active: int64(active), Limit: int64(limit)}
	switch refusal {
	case "global":
		m.watchGlobal++
	case "account":
		m.watchAccount++
	case "node":
		m.watchNode++
	}
}

func (m *Metrics) ReadManagementWatch(p *OperationalPulse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.ManagementWatch = m.managementWatch
	p.WatchGlobal = m.watchGlobal
	p.WatchAccount = m.watchAccount
	p.WatchNode = m.watchNode
}

// QueuePulse contains only a bounded aggregate. When truncated, both the
// count and the measured oldest age are lower bounds.
type QueuePulse struct {
	State         SourceState `json:"state"`
	Count         int         `json:"count"`
	OldestSeconds int64       `json:"oldestSeconds"`
	Truncated     bool        `json:"truncated"`
}

// OperationalPulse is the closed schema used by the admin scrape and the
// Container's periodic log. It carries no tenant or provider identifiers.
type OperationalPulse struct {
	HTTPRequests    Capacity    `json:"httpRequestConnections"`
	GRPCRequests    Capacity    `json:"grpcRequestConnections"`
	HTTPNodes       Capacity    `json:"httpNodeConnections"`
	GRPCNodes       Capacity    `json:"grpcNodeConnections"`
	ManagementWatch Capacity    `json:"managementWatch"`
	WatchGlobal     uint64      `json:"watchGlobalRefusals"`
	WatchAccount    uint64      `json:"watchAccountRefusals"`
	WatchNode       uint64      `json:"watchNodeRefusals"`
	RuntimeDatabase SourceState `json:"runtimeDatabase"`
	SchemaAdmission SourceState `json:"schemaAdmission"`
	RemoteUnknown   QueuePulse  `json:"remoteUnknown"`
	BillingDue      QueuePulse  `json:"billingDue"`
	BillingReview   QueuePulse  `json:"billingReview"`
}

// WritePrometheus emits absent series for disabled sources and for pending
// values whose configured source could not be sampled.
func (p OperationalPulse) WritePrometheus(writer io.Writer) error {
	var text strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&text, "# HELP arcforges_center_%s %s\n# TYPE arcforges_center_%s gauge\n", name, help, name)
	}
	gauge("resource_in_use", "Current reservations by resource.")
	gauge("resource_limit", "Enforced concurrent reservation limits by resource.")
	for _, series := range []struct {
		resource string
		capacity Capacity
	}{
		{"http_request_connections", p.HTTPRequests}, {"grpc_request_connections", p.GRPCRequests},
		{"http_node_connections", p.HTTPNodes}, {"grpc_node_connections", p.GRPCNodes}, {"management_watch", p.ManagementWatch},
	} {
		if series.capacity.Limit > 0 {
			fmt.Fprintf(&text, "arcforges_center_resource_in_use{resource=%q} %d\n", series.resource, series.capacity.Active)
			fmt.Fprintf(&text, "arcforges_center_resource_limit{resource=%q} %d\n", series.resource, series.capacity.Limit)
		}
	}
	if p.ManagementWatch.Limit > 0 {
		text.WriteString("# HELP arcforges_center_watch_refusals_total Management watches refused by the first full scope.\n")
		text.WriteString("# TYPE arcforges_center_watch_refusals_total counter\n")
		fmt.Fprintf(&text, "arcforges_center_watch_refusals_total{scope=\"global\"} %d\n", p.WatchGlobal)
		fmt.Fprintf(&text, "arcforges_center_watch_refusals_total{scope=\"account\"} %d\n", p.WatchAccount)
		fmt.Fprintf(&text, "arcforges_center_watch_refusals_total{scope=\"node\"} %d\n", p.WatchNode)
	}
	gauge("store_ready", "Whether the configured runtime database check succeeded.")
	writeState := func(metric, label, name string, state SourceState) {
		if state == SourceReady || state == SourceUnavailable {
			fmt.Fprintf(&text, "arcforges_center_%s{%s=%q} %d\n", metric, label, name, bit(state == SourceReady))
		}
	}
	writeState("store_ready", "check", "database", p.RuntimeDatabase)
	writeState("store_ready", "check", "schema_admission", p.SchemaAdmission)

	gauge("pending_available", "Whether the configured pending records source was sampled.")
	gauge("pending_items", "Count of sampled pending records.")
	gauge("pending_oldest_seconds", "Age of the oldest sampled pending record in seconds.")
	gauge("pending_truncated", "Whether additional pending records exist past the sample bound.")
	for _, series := range []struct {
		name  string
		queue QueuePulse
	}{
		{"remote_unknown", p.RemoteUnknown}, {"billing_due", p.BillingDue}, {"billing_review", p.BillingReview},
	} {
		writeState("pending_available", "queue", series.name, series.queue.State)
		if series.queue.State == SourceReady {
			fmt.Fprintf(&text, "arcforges_center_pending_items{queue=%q} %d\n", series.name, series.queue.Count)
			fmt.Fprintf(&text, "arcforges_center_pending_oldest_seconds{queue=%q} %d\n", series.name, series.queue.OldestSeconds)
			fmt.Fprintf(&text, "arcforges_center_pending_truncated{queue=%q} %d\n", series.name, bit(series.queue.Truncated))
		}
	}
	_, err := io.WriteString(writer, text.String())
	return err
}

func bit(value bool) int {
	if value {
		return 1
	}
	return 0
}
