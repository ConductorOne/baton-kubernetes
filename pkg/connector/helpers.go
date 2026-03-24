package connector

import (
	"crypto/x509"
	"encoding/pem"
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
// The current phase (ResourceTypeID) is preserved in the next page token so that
// multi-phase callers don't lose their phase across pages.
func HandleKubePagination(respMeta *metav1.ListMeta, bag *pagination.Bag) (string, error) {
	if respMeta == nil || respMeta.Continue == "" {
		return "", nil
	}

	bag.Push(pagination.PageState{
		ResourceTypeID: bag.ResourceTypeID(),
		Token:          respMeta.Continue,
	})

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

// parseCertsFromPEM parses x509 certificates from PEM-encoded data.
func parseCertsFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		pemData = rest
	}
	return certs, nil
}

// containsString returns true if s is present in slice.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
