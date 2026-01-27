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

package dockerhub

import "time"

// RepositoryInfo contains metadata about a Docker Hub repository
type RepositoryInfo struct {
	// Namespace is the Docker Hub namespace (e.g., "library" for official images)
	Namespace string
	// Name is the repository name
	Name string
	// IsOfficial is true if this is a Docker Official Image (namespace == "library")
	IsOfficial bool
	// IsVerifiedPublisher is true if the publisher is a Docker Verified Publisher
	IsVerifiedPublisher bool
	// PullCount is the total number of pulls
	PullCount int64
	// StarCount is the number of stars on Docker Hub
	StarCount int
	// LastUpdated is when the repository was last updated
	LastUpdated time.Time
	// Description is the short description of the repository
	Description string
}

// DockerHubRepositoryResponse represents the response from Docker Hub API
// GET https://hub.docker.com/v2/repositories/{namespace}/{repository}
type DockerHubRepositoryResponse struct {
	User              string    `json:"user"`
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	RepositoryType    string    `json:"repository_type"`
	Status            int       `json:"status"`
	StatusDescription string    `json:"status_description"`
	Description       string    `json:"description"`
	IsPrivate         bool      `json:"is_private"`
	IsAutomated       bool      `json:"is_automated"`
	StarCount         int       `json:"star_count"`
	PullCount         int64     `json:"pull_count"`
	LastUpdated       time.Time `json:"last_updated"`
	DateRegistered    time.Time `json:"date_registered"`

	// ContentTypes indicates the type of content (e.g., "image", "plugin")
	ContentTypes []string `json:"content_types"`

	// Hub-specific fields for trust levels
	// For verified publishers, the namespace will have special properties
}

// DockerHubNamespaceResponse represents namespace info from Docker Hub
// Deprecated: Use DockerHubOrgResponse instead
type DockerHubNamespaceResponse struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	IsVerifiedPublisher bool     `json:"is_verified_publisher"`
	ContentTypes        []string `json:"content_types"`
}

// DockerHubOrgResponse represents organization info from Docker Hub
// GET https://hub.docker.com/v2/orgs/{namespace}
type DockerHubOrgResponse struct {
	ID       string `json:"id"`
	Orgname  string `json:"orgname"`
	FullName string `json:"full_name"`
	Company  string `json:"company"`
	Type     string `json:"type"`
	// Badge indicates the trust level: "verified_publisher", "open_source", etc.
	Badge    string `json:"badge"`
	IsActive bool   `json:"is_active"`
}
