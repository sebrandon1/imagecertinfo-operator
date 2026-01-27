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

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/internal/controller"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/dockerhub"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/pyxis"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)

	// Pyxis configuration flags
	var pyxisEnabled bool
	var pyxisBaseURL string
	var pyxisAPIKey string
	var cleanupInterval time.Duration
	var pyxisCacheTTL time.Duration
	var pyxisRateLimit float64
	var pyxisRateBurst int
	var pyxisRefreshInterval time.Duration

	// Docker Hub configuration flags
	var dockerHubEnabled bool
	var dockerHubCacheTTL time.Duration
	var dockerHubRateLimit float64
	var dockerHubRateBurst int

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	// Pyxis flags
	flag.BoolVar(&pyxisEnabled, "pyxis-enabled", true,
		"Enable Pyxis API integration for Red Hat image certification checks (enabled by default, works without auth)")
	flag.StringVar(&pyxisBaseURL, "pyxis-base-url", pyxis.DefaultBaseURL,
		"Base URL for the Pyxis API")
	flag.StringVar(&pyxisAPIKey, "pyxis-api-key", "",
		"Optional API key for Pyxis authentication (public API works without auth, can also use PYXIS_API_KEY env var)")
	flag.DurationVar(&cleanupInterval, "cleanup-interval", 5*time.Minute,
		"Interval for cleaning up stale pod references")
	flag.DurationVar(&pyxisCacheTTL, "pyxis-cache-ttl", pyxis.DefaultCacheTTL,
		"TTL for cached Pyxis API responses (default 1 hour)")
	flag.Float64Var(&pyxisRateLimit, "pyxis-rate-limit", pyxis.DefaultRateLimit,
		"Rate limit for Pyxis API requests per second (default 10)")
	flag.IntVar(&pyxisRateBurst, "pyxis-rate-burst", pyxis.DefaultRateBurst,
		"Burst size for Pyxis API rate limiting (default 20)")
	flag.DurationVar(&pyxisRefreshInterval, "pyxis-refresh-interval", 24*time.Hour,
		"Interval for periodic refresh of Pyxis certification data (0 to disable, default 24h)")

	// Docker Hub flags
	flag.BoolVar(&dockerHubEnabled, "dockerhub-enabled", true,
		"Enable Docker Hub metadata enrichment for docker.io images")
	flag.DurationVar(&dockerHubCacheTTL, "dockerhub-cache-ttl", dockerhub.DefaultCacheTTL,
		"TTL for cached Docker Hub API responses (default 1 hour)")
	flag.Float64Var(&dockerHubRateLimit, "dockerhub-rate-limit", dockerhub.DefaultRateLimit,
		"Rate limit for Docker Hub API requests per second (default 5)")
	flag.IntVar(&dockerHubRateBurst, "dockerhub-rate-burst", dockerhub.DefaultRateBurst,
		"Burst size for Docker Hub API rate limiting (default 10)")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Check for API key in environment variable if not set via flag
	if pyxisAPIKey == "" {
		pyxisAPIKey = os.Getenv("PYXIS_API_KEY")
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "61c0b778.telco.openshift.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Initialize Pyxis client if enabled
	// The public Pyxis API works without authentication for read-only queries
	var pyxisClient pyxis.Client
	if pyxisEnabled {
		setupLog.Info("Pyxis integration enabled (no auth required for public API)",
			"baseURL", pyxisBaseURL,
			"cacheTTL", pyxisCacheTTL,
			"rateLimit", pyxisRateLimit,
			"rateBurst", pyxisRateBurst)
		clientOpts := []pyxis.ClientOption{
			pyxis.WithBaseURL(pyxisBaseURL),
		}
		if pyxisAPIKey != "" {
			setupLog.Info("Using API key for Pyxis authentication")
			clientOpts = append(clientOpts, pyxis.WithAPIKey(pyxisAPIKey))
		}
		baseClient := pyxis.NewHTTPClient(clientOpts...)

		// Wrap with caching and rate limiting
		pyxisClient = pyxis.NewCachedRateLimitedClient(baseClient, pyxisCacheTTL, pyxisRateLimit, pyxisRateBurst)
	}

	// Initialize Docker Hub client if enabled
	var dockerHubClient dockerhub.Client
	if dockerHubEnabled {
		setupLog.Info("Docker Hub integration enabled",
			"cacheTTL", dockerHubCacheTTL,
			"rateLimit", dockerHubRateLimit,
			"rateBurst", dockerHubRateBurst)
		baseDockerHubClient := dockerhub.NewHTTPClient()

		// Wrap with caching and rate limiting
		dockerHubClient = dockerhub.NewCachedRateLimitedClient(
			baseDockerHubClient, dockerHubCacheTTL, dockerHubRateLimit, dockerHubRateBurst)
	}

	// Set up the Pod controller
	podReconciler := &controller.PodReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		PyxisClient:     pyxisClient,
		DockerHubClient: dockerHubClient,
		Recorder:        mgr.GetEventRecorderFor("imagecertinfo-controller"), //nolint:staticcheck
	}

	if err = podReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	// Start the cleanup loop for stale pod references
	ctx := ctrl.SetupSignalHandler()
	podReconciler.StartCleanupLoop(ctx, cleanupInterval)

	// Start cache cleanup loop if using cached client
	if cachedClient, ok := pyxisClient.(*pyxis.CachedClient); ok {
		cachedClient.StartCleanupLoop(ctx, pyxisCacheTTL/2)
	}

	// Start the periodic refresh loop for Pyxis data
	if pyxisRefreshInterval > 0 && pyxisClient != nil {
		setupLog.Info("Starting Pyxis refresh loop", "interval", pyxisRefreshInterval)
		podReconciler.StartRefreshLoop(ctx, pyxisRefreshInterval)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
