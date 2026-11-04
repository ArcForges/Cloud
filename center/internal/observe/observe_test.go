// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestMetricsAreExposedInThePrometheusTextFormat(t *testing.T) {
	metrics := NewMetrics()
	metrics.ObserveRequest("/arcforges.hello.v1.HelloService/SayHello", "ok", 3*time.Millisecond)
	metrics.ObserveRequest("/arcforges.hello.v1.HelloService/SayHello", "invalid_argument", 20*time.Millisecond)
	metrics.ObserveRequest("plain", "200", time.Millisecond)
	metrics.ObserveRefusal("auth.unauthenticated", "authentication")
	var text bytes.Buffer
	if err := metrics.WritePrometheus(&text); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`arcforges_center_requests_total{method="/arcforges.hello.v1.HelloService/SayHello",code="ok"} 1`,
		`arcforges_center_requests_total{method="/arcforges.hello.v1.HelloService/SayHello",code="invalid_argument"} 1`,
		`arcforges_center_request_duration_seconds_bucket{method="/arcforges.hello.v1.HelloService/SayHello",le="0.005"} 1`,
		`arcforges_center_request_duration_seconds_bucket{method="/arcforges.hello.v1.HelloService/SayHello",le="0.025"} 2`,
		`arcforges_center_request_duration_seconds_bucket{method="/arcforges.hello.v1.HelloService/SayHello",le="+Inf"} 2`,
		`arcforges_center_request_duration_seconds_count{method="plain"} 1`,
		`arcforges_center_refusals_total{code="auth.unauthenticated",category="authentication"} 1`,
		"# TYPE arcforges_center_request_duration_seconds histogram",
	} {
		if !strings.Contains(text.String(), line+"\n") {
			t.Fatalf("missing %s in\n%s", line, text.String())
		}
	}
	summary := metrics.Summary()
	if summary["plain 200"] != 1 || summary["refused auth.unauthenticated authentication"] != 1 {
		t.Fatalf("summary: %v", summary)
	}
}

func TestLogsAreJSONLinesOfTheCenter(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, slog.LevelInfo)
	logger.Debug("hidden")
	logger.Info("request", "correlationId", "4bf92f35-77b3-4da6-a3ce-929d0e0e4736")
	var line map[string]any
	if err := json.Unmarshal(output.Bytes(), &line); err != nil {
		t.Fatalf("not one JSON line: %q", output.String())
	}
	if line["service"] != "arcforges-center" || line["msg"] != "request" || line["correlationId"] == nil || line["level"] != "INFO" {
		t.Fatalf("line: %v", line)
	}
}

// TestFleetMetricLabelsAreClosed (CR-02): every listed fleet pair is exposed as itself, and a pair outside the closed list is never a
// label: it is counted as unlisted, so request content can never become a label value.
func TestFleetMetricLabelsAreClosed(t *testing.T) {
	metrics := NewMetrics()
	listed := 0
	for event, outcomes := range FleetOutcomes() {
		for _, outcome := range outcomes {
			metrics.ObserveFleet(event, outcome)
			listed++
		}
	}
	metrics.ObserveFleet("refresh", "afr1.secret")
	metrics.ObserveFleet("node-name", "rotated")
	var text strings.Builder
	if err := metrics.WritePrometheus(&text); err != nil {
		t.Fatal(err)
	}
	lines := 0
	for line := range strings.SplitSeq(text.String(), "\n") {
		if !strings.HasPrefix(line, "arcforges_center_fleet_events_total{") {
			continue
		}
		lines++
		if strings.Contains(line, "secret") || strings.Contains(line, "node-name") {
			t.Fatalf("a request value became a label: %s", line)
		}
	}
	if lines != listed+1 || !strings.Contains(text.String(), `arcforges_center_fleet_events_total{event="unlisted",outcome="unlisted"} 2`) {
		t.Fatalf("fleet lines %d of %d listed:\n%s", lines, listed, text.String())
	}
}
