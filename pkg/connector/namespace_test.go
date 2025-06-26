package connector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNamespaceBuilderResourceType(t *testing.T) {
	// Create a fake client
	fakeClient := fake.NewSimpleClientset()

	// Create a namespaceBuilder instance using the fake client
	builder := &namespaceBuilder{
		client: fakeClient,
	}

	// Call ResourceType method
	resourceType := builder.ResourceType(context.Background())

	// Verify the result
	assert.Equal(t, ResourceTypeNamespace, resourceType, "Expected ResourceType to return resourceTypeNamespace")
}
