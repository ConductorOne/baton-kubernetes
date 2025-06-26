package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWildcardResources verifies that wildcard resources can be created successfully.
func TestWildcardResources(t *testing.T) {
	testCases := []struct {
		name         string
		resourceType *v2.ResourceType
	}{
		{
			name:         "Secret wildcard",
			resourceType: ResourceTypeSecret,
		},
		{
			name:         "ServiceAccount wildcard",
			resourceType: ResourceTypeServiceAccount,
		},
		{
			name:         "Role wildcard",
			resourceType: ResourceTypeRole,
		},
		{
			name:         "ClusterRole wildcard",
			resourceType: ResourceTypeClusterRole,
		},
		{
			name:         "Pod wildcard",
			resourceType: ResourceTypePod,
		},
		{
			name:         "Node wildcard",
			resourceType: ResourceTypeNode,
		},
		{
			name:         "Namespace wildcard",
			resourceType: ResourceTypeNamespace,
		},
		{
			name:         "ConfigMap wildcard",
			resourceType: ResourceTypeConfigMap,
		},
		{
			name:         "DaemonSet wildcard",
			resourceType: ResourceTypeDaemonSet,
		},
		{
			name:         "Deployment wildcard",
			resourceType: ResourceTypeDeployment,
		},
		{
			name:         "StatefulSet wildcard",
			resourceType: ResourceTypeStatefulSet,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create wildcard resource - if the appropriate traits are missing, this would fail
			resource, err := generateWildcardResource(tc.resourceType)
			require.NoError(t, err)
			require.NotNil(t, resource)

			// Check resource ID and type
			assert.Equal(t, "*", resource.Id.Resource)
			assert.Equal(t, tc.resourceType.Id, resource.Id.ResourceType)
			assert.Contains(t, resource.DisplayName, "All")
		})
	}
}
