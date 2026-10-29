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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
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

func TestUpdateInventory(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	items := []securityv1alpha1.ImageCertificationInfo{
		{
			Status: securityv1alpha1.ImageCertificationInfoStatus{
				CertificationStatus: securityv1alpha1.CertificationStatusCertified,
				DaysUntilEOL:        intPtr(20),
				PyxisData: &securityv1alpha1.PyxisData{
					HealthIndex: "A",
					Vulnerabilities: &securityv1alpha1.VulnerabilitySummary{
						Critical:  2,
						Important: 1,
					},
				},
			},
		},
		{
			Status: securityv1alpha1.ImageCertificationInfoStatus{
				CertificationStatus: securityv1alpha1.CertificationStatusNotCertified,
				DaysUntilEOL:        intPtr(-5),
			},
		},
		{
			Status: securityv1alpha1.ImageCertificationInfoStatus{
				CertificationStatus: securityv1alpha1.CertificationStatusCertified,
				DaysUntilEOL:        intPtr(45),
				PyxisData: &securityv1alpha1.PyxisData{
					HealthIndex: "B",
				},
			},
		},
	}

	UpdateInventory(items)

	tests := []struct {
		name   string
		metric prometheus.Gauge
		want   float64
	}{
		{"certified total", ImagesTotal.WithLabelValues("Certified"), 2},
		{"not certified total", ImagesTotal.WithLabelValues("NotCertified"), 1},
		{"pending total", ImagesTotal.WithLabelValues("Pending"), 0},
		{"health A", ImagesByHealth.WithLabelValues("A"), 1},
		{"health B", ImagesByHealth.WithLabelValues("B"), 1},
		{"health F", ImagesByHealth.WithLabelValues("F"), 0},
		{"critical vulnerabilities", VulnerabilitiesTotal.WithLabelValues("critical"), 2},
		{"important vulnerabilities", VulnerabilitiesTotal.WithLabelValues("important"), 1},
		{"eol within 30", ImagesEOLWithinDays.WithLabelValues("30"), 1},
		{"eol within 60", ImagesEOLWithinDays.WithLabelValues("60"), 2},
		{"eol within 90", ImagesEOLWithinDays.WithLabelValues("90"), 2},
		{"past eol", ImagesPastEOL, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testutil.ToFloat64(tt.metric); got != tt.want {
				t.Errorf("value = %v, want %v", got, tt.want)
			}
		})
	}
}
