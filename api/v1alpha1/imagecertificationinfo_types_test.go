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

package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStatusSupplyChainURIs(t *testing.T) {
	t.Run("omitted from JSON when unset", func(t *testing.T) {
		out, err := json.Marshal(ImageCertificationInfoStatus{})
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		for _, field := range []string{"sbomURI", "attestationURI"} {
			if strings.Contains(string(out), field) {
				t.Errorf("marshalled status contains %q when it is empty: %s", field, out)
			}
		}
	})

	t.Run("round trips the published field names", func(t *testing.T) {
		in := `{"sbomURI":"registry.example.com/app@sha256:abc.att","attestationURI":"https://example.com/att.json"}`

		var status ImageCertificationInfoStatus
		if err := json.Unmarshal([]byte(in), &status); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if status.SBOMURI != "registry.example.com/app@sha256:abc.att" {
			t.Errorf("SBOMURI = %q, want the decoded value", status.SBOMURI)
		}
		if status.AttestationURI != "https://example.com/att.json" {
			t.Errorf("AttestationURI = %q, want the decoded value", status.AttestationURI)
		}

		out, err := json.Marshal(status)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		if string(out) != in {
			t.Errorf("round trip = %s, want %s", out, in)
		}
	})

	t.Run("deep copy carries the URIs", func(t *testing.T) {
		original := &ImageCertificationInfoStatus{
			SBOMURI:        "registry.example.com/app@sha256:abc.att",
			AttestationURI: "https://example.com/att.json",
		}

		copied := original.DeepCopy()
		if copied.SBOMURI != original.SBOMURI || copied.AttestationURI != original.AttestationURI {
			t.Errorf("DeepCopy() = %+v, want it to carry %+v", copied, original)
		}
	})
}
