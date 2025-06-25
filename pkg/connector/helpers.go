package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourcesPageSize is the default page size for resource listings.
const ResourcesPageSize = 500

// ParsePageToken parses a page token into a pagination bag.
func ParsePageToken(token string) (*pagination.Bag, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal page token: %w", err)
	}
	return bag, nil
}

// HandleKubePagination handles Kubernetes pagination and creates a new page token.
func HandleKubePagination(respMeta *metav1.ListMeta, bag *pagination.Bag) (string, error) {
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

// formatResourceID creates a Baton resource ID for the given resource type and ID.
func formatResourceID(resourceType *v2.ResourceType, id string) (*v2.ResourceId, error) {
	if resourceType == nil {
		return nil, fmt.Errorf("resource type is required")
	}

	return &v2.ResourceId{
		ResourceType: resourceType.Id,
		Resource:     id,
	}, nil
}

// NamespaceResourceID creates a Baton resource ID for a namespace.
func NamespaceResourceID(namespace string) (*v2.ResourceId, error) {
	return formatResourceID(ResourceTypeNamespace, namespace)
}
