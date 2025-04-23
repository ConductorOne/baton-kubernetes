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
		return namespacedResourceID(resourceTypeServiceAccount, namespace, subject.Name)
	case "User":
		return clusterScopedResourceID(resourceTypeKubeUser, subject.Name)
	case "Group":
		return clusterScopedResourceID(resourceTypeKubeGroup, subject.Name)
	default:
		return nil, fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}
