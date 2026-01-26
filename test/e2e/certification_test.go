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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sebrandon1/imagecertinfo-operator/test/utils"
)

// testNamespace is where test pods are deployed
const testNamespace = "certification-test"

// certifiedImage is a known Red Hat certified image (using public registry that doesn't require auth)
const certifiedImage = "registry.access.redhat.com/ubi9/ubi-minimal:latest"

// nonCertifiedImage is a public image that is not Red Hat certified
const nonCertifiedImage = "docker.io/library/nginx:alpine"

var _ = Describe("Image Certification Detection", Label("Nightly", "Certification"), Ordered, func() {
	BeforeAll(func() {
		By("creating test namespace")
		cmd := exec.Command("kubectl", "create", "ns", testNamespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd) // Ignore error, may not be supported on all clusters
	})

	AfterAll(func() {
		By("cleaning up test namespace")
		cmd := exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching test namespace events on failure")
			cmd := exec.Command("kubectl", "get", "events", "-n", testNamespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Test namespace events:\n%s", eventsOutput)
			}

			By("Fetching ImageCertificationInfo resources on failure")
			cmd = exec.Command("kubectl", "get", "imagecertificationinfoes", "-o", "yaml")
			iciOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "ImageCertificationInfo resources:\n%s", iciOutput)
			}
		}
	})

	SetDefaultEventuallyTimeout(5 * time.Minute)
	SetDefaultEventuallyPollingInterval(5 * time.Second)

	Context("When a certified Red Hat image is deployed", func() {
		var podName string

		BeforeAll(func() {
			podName = "certified-test-pod"

			By("deploying a pod with a certified Red Hat image")
			podSpec := fmt.Sprintf(`{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "%s",
					"namespace": "%s"
				},
				"spec": {
					"containers": [{
						"name": "ubi",
						"image": "%s",
						"command": ["sleep", "3600"],
						"securityContext": {
							"readOnlyRootFilesystem": true,
							"allowPrivilegeEscalation": false,
							"capabilities": {
								"drop": ["ALL"]
							},
							"runAsNonRoot": true,
							"runAsUser": 1000,
							"seccompProfile": {
								"type": "RuntimeDefault"
							}
						}
					}],
					"restartPolicy": "Never"
				}
			}`, podName, testNamespace, certifiedImage)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(podSpec)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create certified test pod")

			By("waiting for the pod to be running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", podName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Pod not yet running")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			By("cleaning up the certified test pod")
			cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create ImageCertificationInfo with Certified status", func() {
			By("waiting for ImageCertificationInfo to be created")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "imagecertificationinfoes", "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var iciList struct {
					Items []struct {
						Spec struct {
							Registry string `json:"registry"`
						} `json:"spec"`
						Status struct {
							CertificationStatus string `json:"certificationStatus"`
						} `json:"status"`
					} `json:"items"`
				}
				err = json.Unmarshal([]byte(output), &iciList)
				g.Expect(err).NotTo(HaveOccurred())

				// Find the ICI for the Red Hat registry
				var found bool
				for _, ici := range iciList.Items {
					if strings.Contains(ici.Spec.Registry, "registry.access.redhat.com") {
						found = true
						g.Expect(ici.Status.CertificationStatus).To(Equal("Certified"),
							"Expected Certified status for Red Hat image")
					}
				}
				g.Expect(found).To(BeTrue(), "ImageCertificationInfo for registry.access.redhat.com not found")
			}).Should(Succeed())
		})

		It("should populate Pyxis data for certified image", func() {
			By("verifying Pyxis data is populated")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "imagecertificationinfoes", "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var iciList struct {
					Items []struct {
						Spec struct {
							Registry string `json:"registry"`
						} `json:"spec"`
						Status struct {
							CertificationStatus string `json:"certificationStatus"`
							PyxisData           *struct {
								HealthIndex string `json:"healthIndex"`
								Publisher   string `json:"publisher"`
							} `json:"pyxisData"`
						} `json:"status"`
					} `json:"items"`
				}
				err = json.Unmarshal([]byte(output), &iciList)
				g.Expect(err).NotTo(HaveOccurred())

				for _, ici := range iciList.Items {
					if strings.Contains(ici.Spec.Registry, "registry.access.redhat.com") {
						g.Expect(ici.Status.PyxisData).NotTo(BeNil(), "PyxisData should be populated")
						g.Expect(ici.Status.PyxisData.HealthIndex).NotTo(BeEmpty(),
							"HealthIndex should be set")
					}
				}
			}).Should(Succeed())
		})

		It("should track pod references correctly", func() {
			By("verifying pod references contain the test pod")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "imagecertificationinfoes", "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var iciList struct {
					Items []struct {
						Spec struct {
							Registry string `json:"registry"`
						} `json:"spec"`
						Status struct {
							PodReferences []struct {
								Namespace string `json:"namespace"`
								Name      string `json:"name"`
								Container string `json:"container"`
							} `json:"podReferences"`
						} `json:"status"`
					} `json:"items"`
				}
				err = json.Unmarshal([]byte(output), &iciList)
				g.Expect(err).NotTo(HaveOccurred())

				for _, ici := range iciList.Items {
					if strings.Contains(ici.Spec.Registry, "registry.access.redhat.com") {
						var foundPod bool
						for _, ref := range ici.Status.PodReferences {
							if ref.Namespace == testNamespace && ref.Name == podName {
								foundPod = true
								break
							}
						}
						g.Expect(foundPod).To(BeTrue(),
							"Test pod should be in podReferences")
					}
				}
			}).Should(Succeed())
		})
	})

	Context("When a non-certified image is deployed", func() {
		var podName string

		BeforeAll(func() {
			podName = "noncertified-test-pod"

			By("deploying a pod with a non-certified image")
			podSpec := fmt.Sprintf(`{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "%s",
					"namespace": "%s"
				},
				"spec": {
					"containers": [{
						"name": "nginx",
						"image": "%s",
						"securityContext": {
							"readOnlyRootFilesystem": true,
							"allowPrivilegeEscalation": false,
							"capabilities": {
								"drop": ["ALL"]
							},
							"runAsNonRoot": true,
							"runAsUser": 1000,
							"seccompProfile": {
								"type": "RuntimeDefault"
							}
						}
					}],
					"restartPolicy": "Never"
				}
			}`, podName, testNamespace, nonCertifiedImage)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(podSpec)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create non-certified test pod")

			By("waiting for the pod to be running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", podName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Pod not yet running")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			By("cleaning up the non-certified test pod")
			cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create ImageCertificationInfo with non-Certified status", func() {
			By("waiting for ImageCertificationInfo to be created")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "imagecertificationinfoes", "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				var iciList struct {
					Items []struct {
						Spec struct {
							Registry string `json:"registry"`
						} `json:"spec"`
						Status struct {
							CertificationStatus string `json:"certificationStatus"`
							RegistryType        string `json:"registryType"`
						} `json:"status"`
					} `json:"items"`
				}
				err = json.Unmarshal([]byte(output), &iciList)
				g.Expect(err).NotTo(HaveOccurred())

				// Find the ICI for the Docker Hub registry
				var found bool
				for _, ici := range iciList.Items {
					if strings.Contains(ici.Spec.Registry, "docker.io") ||
						strings.Contains(ici.Spec.Registry, "index.docker.io") {
						found = true
						// Non-Red Hat images should not be "Certified"
						g.Expect(ici.Status.CertificationStatus).NotTo(Equal("Certified"),
							"Docker Hub image should not be Certified")
					}
				}
				g.Expect(found).To(BeTrue(), "ImageCertificationInfo for docker.io not found")
			}).Should(Succeed())
		})
	})
})
