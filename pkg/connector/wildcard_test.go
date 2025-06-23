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
			resourceType: resourceTypeSecret,
		},
		{
			name:         "ServiceAccount wildcard",
			resourceType: resourceTypeServiceAccount,
		},
		{
			name:         "Role wildcard",
			resourceType: resourceTypeRole,
		},
		{
			name:         "ClusterRole wildcard",
			resourceType: resourceTypeClusterRole,
		},
		{
			name:         "Pod wildcard",
			resourceType: resourceTypePod,
		},
		{
			name:         "Node wildcard",
			resourceType: resourceTypeNode,
		},
		{
			name:         "Namespace wildcard",
			resourceType: resourceTypeNamespace,
		},
		{
			name:         "ConfigMap wildcard",
			resourceType: resourceTypeConfigMap,
		},
		{
			name:         "DaemonSet wildcard",
			resourceType: resourceTypeDaemonSet,
		},
		{
			name:         "Deployment wildcard",
			resourceType: resourceTypeDeployment,
		},
		{
			name:         "StatefulSet wildcard",
			resourceType: resourceTypeStatefulSet,
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
