// Package metrics is a minimal Prometheus text-format registry (M0,
// docs/platformization-plan-v1.md §4). It intentionally replaces the full
// client_golang dependency with a tiny stdlib-only implementation: counters and
// gauges with optional string labels, rendered as the classic exposition format
// so any Prometheus/Grafana/telegraf scraper can consume /metrics.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Registry holds all metrics. Safe for concurrent use; one lock guards values.
type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*metric
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{metrics: map[string]*metric{}}
}

type metric struct {
	name    string
	help    string
	labels  []string           // label names (fixed at registration)
	values  map[string]float64 // key: joined label values
	isGauge bool
}

func (m *metric) key(labelValues []string) string {
	if len(m.labels) == 0 {
		return ""
	}
	if len(labelValues) != len(m.labels) {
		panic(fmt.Sprintf("metrics: %s got %d label values, want %d", m.name, len(labelValues), len(m.labels)))
	}
	return strings.Join(labelValues, "\x00")
}

// Counter registers (or returns) a monotonic counter. name should already carry
// a _total suffix per Prometheus naming convention.
func (r *Registry) Counter(name, help string, labelNames ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.metrics[name]
	if !ok {
		m = &metric{name: name, help: help, labels: labelNames, values: map[string]float64{}}
		r.metrics[name] = m
	}
	return &Counter{r: r, m: m}
}

// Gauge registers (or returns) a gauge (rises and falls).
func (r *Registry) Gauge(name, help string, labelNames ...string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.metrics[name]
	if !ok {
		m = &metric{name: name, help: help, labels: labelNames, values: map[string]float64{}, isGauge: true}
		r.metrics[name] = m
	}
	return &Gauge{r: r, m: m}
}

// Counter is a monotonic counter handle.
type Counter struct {
	r *Registry
	m *metric
}

// Inc adds delta (use 1 for a plain increment).
func (c *Counter) Inc(delta float64, labelValues ...string) {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	c.m.values[c.m.key(labelValues)] += delta
}

// Get returns the current value for the given label combo (0 when absent).
func (c *Counter) Get(labelValues ...string) float64 {
	c.r.mu.RLock()
	defer c.r.mu.RUnlock()
	return c.m.values[c.m.key(labelValues)]
}

// Gauge is a settable gauge handle.
type Gauge struct {
	r *Registry
	m *metric
}

// Set replaces the value.
func (g *Gauge) Set(v float64, labelValues ...string) {
	g.r.mu.Lock()
	defer g.r.mu.Unlock()
	g.m.values[g.m.key(labelValues)] = v
}

// Add deltas the gauge.
func (g *Gauge) Add(d float64, labelValues ...string) {
	g.r.mu.Lock()
	defer g.r.mu.Unlock()
	g.m.values[g.m.key(labelValues)] += d
}

// Get returns the current value for the given label combo.
func (g *Gauge) Get(labelValues ...string) float64 {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	return g.m.values[g.m.key(labelValues)]
}

// Text renders the whole registry in Prometheus text exposition format
// (https://prometheus.io/docs/instrumenting/exposition_formats/#text-format).
// Series are sorted by name then label set for deterministic output.
func (r *Registry) Text() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		m := r.metrics[name]
		if m.help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", m.name, m.help)
		}
		typ := "counter"
		if m.isGauge {
			typ = "gauge"
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", m.name, typ)

		keys := make([]string, 0, len(m.values))
		for k := range m.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			series := m.name
			if k != "" {
				parts := strings.Split(k, "\x00")
				var sb strings.Builder
				sb.WriteString(m.name)
				sb.WriteByte('{')
				for i, p := range parts {
					if i > 0 {
						sb.WriteByte(',')
					}
					fmt.Fprintf(&sb, "%s=%q", m.labels[i], p)
				}
				sb.WriteByte('}')
				series = sb.String()
			}
			fmt.Fprintf(&b, "%s %g\n", series, m.values[k])
		}
	}
	return b.String()
}

// Handler serves the registry as text at /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(r.Text()))
	})
}
