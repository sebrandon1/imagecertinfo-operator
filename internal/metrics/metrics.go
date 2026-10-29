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
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
)

const (
	// MetricsNamespace is the namespace for all imagecertinfo metrics
	MetricsNamespace = "imagecertinfo"

	labelStatus   = "status"
	labelEndpoint = "endpoint"
	labelResult   = "result"
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
		[]string{labelStatus},
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
		[]string{labelStatus, labelEndpoint},
	)

	// PyxisRequestDuration tracks Pyxis API request duration
	PyxisRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "pyxis_request_duration_seconds",
			Help:      "Duration of Pyxis API requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{labelEndpoint},
	)

	// PyxisCacheHits tracks cache hit/miss ratio
	PyxisCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "pyxis_cache_hits_total",
			Help:      "Total number of Pyxis cache hits and misses",
		},
		[]string{labelResult},
	)

	// Reconciliation Metrics

	// ReconcileTotal tracks total reconciliation attempts
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_total",
			Help:      "Total number of reconciliation attempts",
		},
		[]string{labelResult},
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

	// Docker Hub API Metrics

	// DockerHubRequestsTotal tracks total Docker Hub API requests
	DockerHubRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "dockerhub_requests_total",
			Help:      "Total number of Docker Hub API requests",
		},
		[]string{labelStatus, labelEndpoint},
	)

	// DockerHubRequestDuration tracks Docker Hub API request duration
	DockerHubRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "dockerhub_request_duration_seconds",
			Help:      "Duration of Docker Hub API requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{labelEndpoint},
	)

	// DockerHubCacheHits tracks cache hit/miss ratio
	DockerHubCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "dockerhub_cache_hits_total",
			Help:      "Total number of Docker Hub cache hits and misses",
		},
		[]string{labelResult},
	)

	// Quay.io API Metrics

	// QuayRequestsTotal tracks total Quay.io API requests
	QuayRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "quay_requests_total",
			Help:      "Total number of Quay.io API requests",
		},
		[]string{labelStatus, labelEndpoint},
	)

	// QuayRequestDuration tracks Quay.io API request duration
	QuayRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "quay_request_duration_seconds",
			Help:      "Duration of Quay.io API requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{labelEndpoint},
	)

	// QuayCacheHits tracks cache hit/miss ratio
	QuayCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "quay_cache_hits_total",
			Help:      "Total number of Quay.io cache hits and misses",
		},
		[]string{labelResult},
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
		// Docker Hub API metrics
		DockerHubRequestsTotal,
		DockerHubRequestDuration,
		DockerHubCacheHits,
		// Quay.io API metrics
		QuayRequestsTotal,
		QuayRequestDuration,
		QuayCacheHits,
	)
}

// EOLWindows are the horizons reported by the images_eol_within_days gauge.
var EOLWindows = []int{30, 60, 90}

// inventoryStatuses, inventoryGrades and vulnSeverities are the label values
// the inventory gauges always expose, so a query returns a zero series instead
// of nothing while the matching images do not exist yet.
var (
	inventoryStatuses = []string{"Certified", "NotCertified", "Pending", "Unknown", "Error"}
	inventoryGrades   = []string{"A", "B", "C", "D", "E", "F"}
	vulnSeverities    = []string{"critical", "important", "moderate", "low"}
)

// UpdateInventory recomputes the image inventory gauges from the current set of
// ImageCertificationInfo resources. The gauge vectors are reset first so label
// values for deleted images do not linger.
func UpdateInventory(items []securityv1alpha1.ImageCertificationInfo) {
	ImagesTotal.Reset()
	ImagesByHealth.Reset()
	VulnerabilitiesTotal.Reset()
	ImagesEOLWithinDays.Reset()

	pastEOL := 0

	for i := range items {
		cr := &items[i]

		status := string(cr.Status.CertificationStatus)
		if status == "" {
			status = "Unknown"
		}
		ImagesTotal.WithLabelValues(status).Inc()

		if cr.Status.PyxisData != nil {
			if grade := cr.Status.PyxisData.HealthIndex; grade != "" {
				ImagesByHealth.WithLabelValues(grade).Inc()
			}
			if v := cr.Status.PyxisData.Vulnerabilities; v != nil {
				VulnerabilitiesTotal.WithLabelValues("critical").Add(float64(v.Critical))
				VulnerabilitiesTotal.WithLabelValues("important").Add(float64(v.Important))
				VulnerabilitiesTotal.WithLabelValues("moderate").Add(float64(v.Moderate))
				VulnerabilitiesTotal.WithLabelValues("low").Add(float64(v.Low))
			}
		}

		if cr.Status.DaysUntilEOL == nil {
			continue
		}
		days := *cr.Status.DaysUntilEOL
		if days < 0 {
			pastEOL++
			continue
		}
		for _, window := range EOLWindows {
			if days <= window {
				ImagesEOLWithinDays.WithLabelValues(strconv.Itoa(window)).Inc()
			}
		}
	}

	ImagesPastEOL.Set(float64(pastEOL))

	// Publish every documented label value, including the ones at zero.
	for _, status := range inventoryStatuses {
		ImagesTotal.WithLabelValues(status).Add(0)
	}
	for _, grade := range inventoryGrades {
		ImagesByHealth.WithLabelValues(grade).Add(0)
	}
	for _, severity := range vulnSeverities {
		VulnerabilitiesTotal.WithLabelValues(severity).Add(0)
	}
	for _, window := range EOLWindows {
		ImagesEOLWithinDays.WithLabelValues(strconv.Itoa(window)).Add(0)
	}
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

// RecordDockerHubRequest records a Docker Hub API request metric
func RecordDockerHubRequest(status, endpoint string, durationSeconds float64) {
	DockerHubRequestsTotal.WithLabelValues(status, endpoint).Inc()
	DockerHubRequestDuration.WithLabelValues(endpoint).Observe(durationSeconds)
}

// RecordDockerHubCacheHit records a Docker Hub cache hit
func RecordDockerHubCacheHit() {
	DockerHubCacheHits.WithLabelValues("hit").Inc()
}

// RecordDockerHubCacheMiss records a Docker Hub cache miss
func RecordDockerHubCacheMiss() {
	DockerHubCacheHits.WithLabelValues("miss").Inc()
}

// RecordQuayRequest records a Quay.io API request metric
func RecordQuayRequest(status, endpoint string, durationSeconds float64) {
	QuayRequestsTotal.WithLabelValues(status, endpoint).Inc()
	QuayRequestDuration.WithLabelValues(endpoint).Observe(durationSeconds)
}

// RecordQuayCacheHit records a Quay.io cache hit
func RecordQuayCacheHit() {
	QuayCacheHits.WithLabelValues("hit").Inc()
}

// RecordQuayCacheMiss records a Quay.io cache miss
func RecordQuayCacheMiss() {
	QuayCacheHits.WithLabelValues("miss").Inc()
}
