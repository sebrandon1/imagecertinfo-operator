//go:build e2e
// +build e2e

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

package e2e

import (
	"os"
	"os/exec"
	"strings"

	"github.com/sebrandon1/imagecertinfo-operator/test/utils"
)

// ClusterType represents the type of Kubernetes cluster
type ClusterType string

const (
	// ClusterTypeKubernetes represents a standard Kubernetes cluster
	ClusterTypeKubernetes ClusterType = "kubernetes"
	// ClusterTypeOpenShift represents an OpenShift cluster
	ClusterTypeOpenShift ClusterType = "openshift"
)

// GetClusterType returns the cluster type based on environment variable or detection
func GetClusterType() ClusterType {
	// Check environment variable first
	if clusterType := os.Getenv("CLUSTER_TYPE"); clusterType != "" {
		switch strings.ToLower(clusterType) {
		case "openshift", "ocp":
			return ClusterTypeOpenShift
		case "kubernetes", "k8s":
			return ClusterTypeKubernetes
		}
	}

	// Auto-detect by checking for OpenShift-specific resources
	if IsOpenShiftCluster() {
		return ClusterTypeOpenShift
	}

	return ClusterTypeKubernetes
}

// IsOpenShiftCluster detects if the current cluster is OpenShift
func IsOpenShiftCluster() bool {
	// Check for OpenShift-specific API resources
	cmd := exec.Command("kubectl", "api-resources", "--api-group=route.openshift.io")
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}

	// If route.openshift.io resources exist, it's OpenShift
	return strings.Contains(output, "routes")
}

// GetCertifiedTestImage returns an appropriate certified image for testing
// based on the cluster type
func GetCertifiedTestImage() string {
	clusterType := GetClusterType()

	switch clusterType {
	case ClusterTypeOpenShift:
		// On OpenShift, we can use internal registry images
		return "registry.access.redhat.com/ubi9/ubi-minimal:latest"
	default:
		// On Kubernetes, use publicly accessible certified image
		return "registry.access.redhat.com/ubi9/ubi-minimal:latest"
	}
}

// GetNonCertifiedTestImage returns a non-certified image for testing
func GetNonCertifiedTestImage() string {
	return "docker.io/library/nginx:alpine"
}

// HasPullSecretForRedHat checks if the cluster has credentials to pull Red Hat images
func HasPullSecretForRedHat() bool {
	// Check if we can access Red Hat registry by looking for pull secrets
	cmd := exec.Command("kubectl", "get", "secret", "-n", "openshift-config", "pull-secret", "-o", "name")
	_, err := utils.Run(cmd)
	if err == nil {
		return true
	}

	// Check for docker config secrets in default namespace
	cmd = exec.Command("kubectl", "get", "secrets", "-o", "jsonpath={.items[*].type}")
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}

	return strings.Contains(output, "kubernetes.io/dockerconfigjson")
}
