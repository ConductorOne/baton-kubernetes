package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// TestRoleBuilderResourceType tests the ResourceType method of the roleBuilder.
func TestRoleBuilderResourceType(t *testing.T) {
	// Create a fake client
	fakeClient := fake.NewSimpleClientset()

	// Create a roleBuilder instance using the fake client
	builder := &roleBuilder{
		client: fakeClient,
	}

	// Call ResourceType method
	resourceType := builder.ResourceType(context.Background())

	// Verify the result
	assert.Equal(t, ResourceTypeRole, resourceType, "Expected ResourceType to return resourceTypeRole")
}

// TestRoleBuilderEntitlements tests the Entitlements method of the roleBuilder.
func TestRoleBuilderEntitlements(t *testing.T) {
	// Create a fake client
	fakeClient := fake.NewSimpleClientset()

	// Create a roleBuilder instance using the fake client
	builder := &roleBuilder{
		client: fakeClient,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeRole.Id,
			Resource:     "test-namespace/test-role",
		},
		DisplayName: "test-role",
	}

	// Call Entitlements method
	ctx := context.Background()
	pToken := &pagination.Token{}
	entitlements, nextPageToken, ann, err := builder.Entitlements(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)
	require.Nil(t, ann)
	assert.Empty(t, nextPageToken)

	// Roles should have 1 entitlements: member
	require.Len(t, entitlements, 1)

	assert.Contains(t, entitlements[0].Description, "membership")
	assert.Len(t, entitlements[0].GrantableTo, 3) // KubeUser, KubeGroup, ServiceAccount
}
