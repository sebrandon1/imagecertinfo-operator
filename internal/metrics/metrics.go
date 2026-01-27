/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// MetricsNamespace is the namespace for all imagecertinfo metrics
	MetricsNamespace = "imagecertinfo"
)

var (
	// Image Inventory Metrics

	// ImagesTotal tracks total images by certification status
	ImagesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "images_total",
			Help:      "Total number of images tracked by certification status",
		},
		[]string{"status"},
	)

	// ImagesByHealth tracks images by health grade
	ImagesByHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "images_by_health",
			Help:      "Number of images by health grade (A-F)",
		},
		[]string{"grade"},
	)

	// VulnerabilitiesTotal tracks total vulnerabilities across all images by severity
	VulnerabilitiesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "vulnerabilities_total",
			Help:      "Total number of vulnerabilities across all images by severity",
		},
		[]string{"severity"},
	)

	// ImagesEOLWithinDays tracks images approaching end-of-life
	ImagesEOLWithinDays = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "images_eol_within_days",
			Help:      "Number of images reaching end-of-life within specified days",
		},
		[]string{"days"},
	)

	// ImagesPastEOL tracks images that have passed their EOL date
	ImagesPastEOL = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "images_past_eol",
			Help:      "Number of images that have passed their end-of-life date",
		},
	)

	// Pyxis API Metrics

	// PyxisRequestsTotal tracks total Pyxis API requests
	PyxisRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "pyxis_requests_total",
			Help:      "Total number of Pyxis API requests",
		},
		[]string{"status", "endpoint"},
	)

	// PyxisRequestDuration tracks Pyxis API request duration
	PyxisRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "pyxis_request_duration_seconds",
			Help:      "Duration of Pyxis API requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"endpoint"},
	)

	// PyxisCacheHits tracks cache hit/miss ratio
	PyxisCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "pyxis_cache_hits_total",
			Help:      "Total number of Pyxis cache hits and misses",
		},
		[]string{"result"}, // "hit" or "miss"
	)

	// Reconciliation Metrics

	// ReconcileTotal tracks total reconciliation attempts
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_total",
			Help:      "Total number of reconciliation attempts",
		},
		[]string{"result"}, // "success", "error", "requeue"
	)

	// ReconcileDuration tracks reconciliation duration
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconciliation in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5},
		},
		[]string{"controller"},
	)

	// ImagesDiscovered tracks new images discovered
	ImagesDiscovered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "images_discovered_total",
			Help:      "Total number of new images discovered",
		},
	)

	// Event Metrics

	// EventsEmitted tracks events emitted by the operator
	EventsEmitted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "events_emitted_total",
			Help:      "Total number of Kubernetes events emitted",
		},
		[]string{"type", "reason"},
	)

	// Refresh Cycle Metrics

	// RefreshCyclesTotal tracks completed refresh cycles
	RefreshCyclesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "refresh_cycles_total",
			Help:      "Total number of completed image refresh cycles",
		},
	)

	// RefreshDurationSeconds tracks refresh cycle duration
	RefreshDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "refresh_duration_seconds",
			Help:      "Duration of image refresh cycles in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
	)

	// ImagesRefreshedTotal tracks individual images refreshed
	ImagesRefreshedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "images_refreshed_total",
			Help:      "Total number of individual images refreshed",
		},
	)

	// CertificationStatusChangesTotal tracks certification status changes
	CertificationStatusChangesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "certification_status_changes_total",
			Help:      "Total number of certification status changes",
		},
		[]string{"from", "to"},
	)
)

func init() {
	// Register all metrics with the controller-runtime metrics registry
	metrics.Registry.MustRegister(
		// Image inventory metrics
		ImagesTotal,
		ImagesByHealth,
		VulnerabilitiesTotal,
		ImagesEOLWithinDays,
		ImagesPastEOL,
		// Pyxis API metrics
		PyxisRequestsTotal,
		PyxisRequestDuration,
		PyxisCacheHits,
		// Reconciliation metrics
		ReconcileTotal,
		ReconcileDuration,
		ImagesDiscovered,
		// Event metrics
		EventsEmitted,
		// Refresh cycle metrics
		RefreshCyclesTotal,
		RefreshDurationSeconds,
		ImagesRefreshedTotal,
		CertificationStatusChangesTotal,
	)
}

// RecordPyxisRequest records a Pyxis API request metric
func RecordPyxisRequest(status, endpoint string, durationSeconds float64) {
	PyxisRequestsTotal.WithLabelValues(status, endpoint).Inc()
	PyxisRequestDuration.WithLabelValues(endpoint).Observe(durationSeconds)
}

// RecordCacheHit records a cache hit
func RecordCacheHit() {
	PyxisCacheHits.WithLabelValues("hit").Inc()
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss() {
	PyxisCacheHits.WithLabelValues("miss").Inc()
}

// RecordReconcile records a reconciliation result
func RecordReconcile(result string, durationSeconds float64, controller string) {
	ReconcileTotal.WithLabelValues(result).Inc()
	ReconcileDuration.WithLabelValues(controller).Observe(durationSeconds)
}

// RecordEvent records an event emission
func RecordEvent(eventType, reason string) {
	EventsEmitted.WithLabelValues(eventType, reason).Inc()
}

// RecordRefreshCycle records a completed refresh cycle
func RecordRefreshCycle(durationSeconds float64) {
	RefreshCyclesTotal.Inc()
	RefreshDurationSeconds.Observe(durationSeconds)
}

// RecordImageRefreshed records an individual image refresh
func RecordImageRefreshed() {
	ImagesRefreshedTotal.Inc()
}

// RecordCertificationStatusChange records a certification status change
func RecordCertificationStatusChange(from, to string) {
	CertificationStatusChangesTotal.WithLabelValues(from, to).Inc()
}
