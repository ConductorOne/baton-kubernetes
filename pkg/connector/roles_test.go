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

// TestRoleBuilderResourceType tests the ResourceType method of the roleBuilder
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
	assert.Equal(t, resourceTypeRole, resourceType, "Expected ResourceType to return resourceTypeRole")
}

// TestRoleBuilderEntitlements tests the Entitlements method of the roleBuilder
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
			ResourceType: resourceTypeRole.Id,
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

	// Roles should have 3 entitlements: member, bind, and escalate
	require.Len(t, entitlements, 3)

	// Check for specific entitlements
	var foundMember, foundBind, foundEscalate bool
	for _, ent := range entitlements {
		switch ent.DisplayName {
		case "test-role Role Member":
			foundMember = true
			assert.Contains(t, ent.Description, "membership")
			assert.Len(t, ent.GrantableTo, 3) // KubeUser, KubeGroup, ServiceAccount
		case "Bind test-role":
			foundBind = true
			assert.Contains(t, ent.Description, "bind")
		case "Escalate test-role":
			foundEscalate = true
			assert.Contains(t, ent.Description, "escalate")
		}
	}

	assert.True(t, foundMember, "member entitlement should be present")
	assert.True(t, foundBind, "bind entitlement should be present")
	assert.True(t, foundEscalate, "escalate entitlement should be present")
}
