package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourcesPageSize is the default page size for resource listings
const ResourcesPageSize = 500

// parsePageToken parses a page token into a pagination bag
func parsePageToken(token string) (*pagination.Bag, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal page token: %w", err)
	}
	return bag, nil
}

// handleKubePagination handles Kubernetes pagination and creates a new page token
func handleKubePagination(respMeta *metav1.ListMeta, bag *pagination.Bag) (string, error) {
	if respMeta.Continue != "" {
		bag.Push(pagination.PageState{
			Token: respMeta.Continue,
		})
	}

	token, err := bag.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal pagination bag: %w", err)
	}

	return token, nil
}

// formatResourceID creates a Baton resource ID for the given resource type and ID
func formatResourceID(resourceType *v2.ResourceType, id string) (*v2.ResourceId, error) {
	if resourceType == nil {
		return nil, fmt.Errorf("resource type is required")
	}

	// Allow ids with special characters like colons or wildcards
	return &v2.ResourceId{
		ResourceType: resourceType.Id,
		Resource:     id,
	}, nil
}

// namespacedResourceID creates a Baton resource ID for a namespaced resource
func namespacedResourceID(resourceType *v2.ResourceType, namespace string, name string) (*v2.ResourceId, error) {
	// Handle special cases for wildcards
	if namespace == "*" && name == "*" {
		return formatResourceID(resourceType, "*")
	}

	id := namespace + "/" + name
	return formatResourceID(resourceType, id)
}

// clusterScopedResourceID creates a Baton resource ID for a cluster-scoped resource
func clusterScopedResourceID(resourceType *v2.ResourceType, name string) (*v2.ResourceId, error) {
	// Allow cluster-scoped resources to have special characters like colons
	return formatResourceID(resourceType, name)
}

// namespaceResourceID creates a Baton resource ID for a namespace
func namespaceResourceID(namespace string) (*v2.ResourceId, error) {
	return formatResourceID(resourceTypeNamespace, namespace)
}
