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
	"testing"

	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestMetricsRegistered(t *testing.T) {
	// Prometheus does not expose an uninitialized vector in Gather(). Initialize
	// each vector so this test covers every registered metric family.
	ImagesTotal.WithLabelValues("test")
	ImagesByHealth.WithLabelValues("test")
	VulnerabilitiesTotal.WithLabelValues("test")
	ImagesEOLWithinDays.WithLabelValues("test")
	PyxisRequestsTotal.WithLabelValues("test", "test")
	PyxisRequestDuration.WithLabelValues("test")
	PyxisCacheHits.WithLabelValues("test")
	ReconcileTotal.WithLabelValues("test")
	ReconcileDuration.WithLabelValues("test")
	EventsEmitted.WithLabelValues("test", "test")
	CertificationStatusChangesTotal.WithLabelValues("test", "test")
	DockerHubRequestsTotal.WithLabelValues("test", "test")
	DockerHubRequestDuration.WithLabelValues("test")
	DockerHubCacheHits.WithLabelValues("test")
	QuayRequestsTotal.WithLabelValues("test", "test")
	QuayRequestDuration.WithLabelValues("test")
	QuayCacheHits.WithLabelValues("test")

	metricFamilies, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather registered metrics: %v", err)
	}

	wantNames := map[string]struct{}{
		"imagecertinfo_images_total":                       {},
		"imagecertinfo_images_by_health":                   {},
		"imagecertinfo_vulnerabilities_total":              {},
		"imagecertinfo_images_eol_within_days":             {},
		"imagecertinfo_images_past_eol":                    {},
		"imagecertinfo_pyxis_requests_total":               {},
		"imagecertinfo_pyxis_request_duration_seconds":     {},
		"imagecertinfo_pyxis_cache_hits_total":             {},
		"imagecertinfo_reconcile_total":                    {},
		"imagecertinfo_reconcile_duration_seconds":         {},
		"imagecertinfo_images_discovered_total":            {},
		"imagecertinfo_events_emitted_total":               {},
		"imagecertinfo_refresh_cycles_total":               {},
		"imagecertinfo_refresh_duration_seconds":           {},
		"imagecertinfo_images_refreshed_total":             {},
		"imagecertinfo_certification_status_changes_total": {},
		"imagecertinfo_dockerhub_requests_total":           {},
		"imagecertinfo_dockerhub_request_duration_seconds": {},
		"imagecertinfo_dockerhub_cache_hits_total":         {},
		"imagecertinfo_quay_requests_total":                {},
		"imagecertinfo_quay_request_duration_seconds":      {},
		"imagecertinfo_quay_cache_hits_total":              {},
	}

	gotNames := make(map[string]struct{}, len(metricFamilies))
	for _, family := range metricFamilies {
		name := family.GetName()
		gotNames[name] = struct{}{}
	}

	if len(gotNames) != len(wantNames) {
		t.Errorf("registered metric count = %d, want %d; got %v", len(gotNames), len(wantNames), gotNames)
	}
	for name := range wantNames {
		if _, ok := gotNames[name]; !ok {
			t.Errorf("metric %q was not registered", name)
		}
	}
}
