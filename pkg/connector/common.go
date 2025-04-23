package connector

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

// mapSubjectToPrincipalID converts a Kubernetes Subject to a Baton ResourceID
func mapSubjectToPrincipalID(subject rbacv1.Subject, defaultNamespace string) (*v2.ResourceId, error) {
	switch subject.Kind {
	case "ServiceAccount":
		namespace := subject.Namespace
		if namespace == "" {
			if defaultNamespace == "" {
				return nil, fmt.Errorf("service account subject must specify a namespace")
			}
			namespace = defaultNamespace
		}
		// Create a safe resource ID that handles special characters
		return &v2.ResourceId{
			ResourceType: resourceTypeServiceAccount.Id,
			Resource:     namespace + "/" + subject.Name,
		}, nil
	case "User":
		// Handle special characters in user names (like system:masters)
		return &v2.ResourceId{
			ResourceType: resourceTypeKubeUser.Id,
			Resource:     subject.Name,
		}, nil
	case "Group":
		// Handle special characters in group names (like system:authenticated)
		return &v2.ResourceId{
			ResourceType: resourceTypeKubeGroup.Id,
			Resource:     subject.Name,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}
